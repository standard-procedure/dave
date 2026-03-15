# frozen_string_literal: true

require "bindata"
require "samba_dave/protocol/constants"

module SambaDave
  module Protocol
    module Commands
      # SMB2 QUERY_DIRECTORY Request body (MS-SMB2 section 2.2.33)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize          — always 33
      #  2       1    FileInformationClass   — e.g. FileBothDirectoryInformation (0x03)
      #  3       1    Flags                  — 0x01=RESTART, 0x02=SINGLE, 0x04=INDEX
      #  4       4    FileIndex              — (used with INDEX flag)
      #  8       8    FileId.Persistent
      # 16       8    FileId.Volatile
      # 24       2    FileNameOffset         — offset from SMB2 header
      # 26       2    FileNameLength         — bytes
      # 28       4    OutputBufferLength     — max response size
      # 32      var   FileName               — search pattern (UTF-16LE)
      #
      class QueryDirectoryRequest < BinData::Record
        endian :little

        uint16 :structure_size
        uint8  :file_information_class
        uint8  :flags
        uint32 :file_index,           initial_value: 0
        uint64 :file_id_persistent
        uint64 :file_id_volatile
        uint16 :file_name_offset
        uint16 :file_name_length
        uint32 :output_buffer_length
      end

      # SMB2 QUERY_DIRECTORY Response body (MS-SMB2 section 2.2.34)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize          — always 9 (includes 1 variable byte)
      #  2       2    OutputBufferOffset     — offset from SMB2 header (64 + 8 = 72)
      #  4       4    OutputBufferLength
      #  8      var   OutputBuffer           — array of directory entry structures
      #
      class QueryDirectoryResponse < BinData::Record
        endian :little

        uint16 :structure_size,        value: 9
        uint16 :output_buffer_offset,  initial_value: 72
        uint32 :output_buffer_length,  initial_value: 0
        string :output_buffer,         read_length: :output_buffer_length
      end

      # Handles the SMB2 QUERY_DIRECTORY command.
      #
      # Lists directory contents using the per-FileId enumeration cursor stored
      # in the OpenFile. Each call advances the cursor; STATUS_NO_MORE_FILES is
      # returned when all entries have been enumerated.
      #
      # Supported FileInformationClass values:
      #   0x03 = FileBothDirectoryInformation
      #   0x25 = FileIdBothDirectoryInformation (adds 8-byte FileId at end)
      #
      module QueryDirectory
        SMB_HEADER_SIZE = 64

        # Flags
        FLAG_RESTART_SCANS   = 0x01
        FLAG_RETURN_SINGLE   = 0x02
        FLAG_INDEX_SPECIFIED = 0x04
        FLAG_REOPEN          = 0x10

        # FileInformationClass
        FILE_BOTH_DIR_INFO      = 0x03
        FILE_ID_BOTH_DIR_INFO   = 0x25
        FILE_ID_FULL_DIR_INFO   = 0x26  # Windows Explorer — like FileIdBothDir but no short name

        # @param body [String] raw request body
        # @param open_file_table [OpenFileTable]
        # @return [Hash] { status:, body: }
        def self.handle(body, open_file_table:)
          request = QueryDirectoryRequest.read(body)

          file_id_bytes = [request.file_id_persistent, request.file_id_volatile].pack("Q<Q<")
          open_file     = open_file_table.get(file_id_bytes)

          return { status: Constants::Status::INVALID_HANDLE, body: "" } unless open_file

          # Extract search pattern from the buffer
          buf_start      = request.file_name_offset - SMB_HEADER_SIZE
          pattern_bytes  = body.b[buf_start, request.file_name_length] || ""
          pattern        = pattern_bytes.force_encoding("UTF-16LE").encode("UTF-8", invalid: :replace, undef: :replace)
          pattern        = "*" if pattern.empty?

          flags = request.flags

          # RESTART_SCANS or REOPEN: reset the enumeration cursor
          if (flags & FLAG_RESTART_SCANS) != 0 || (flags & FLAG_REOPEN) != 0
            open_file.enum_cursor = 0
          end

          # Build the full entry list (. + .. + children) the first time
          # or reuse the cached list (stored as entries from cursor position)
          entries = build_entries(open_file, pattern)

          cursor = open_file.enum_cursor
          if cursor >= entries.size
            return { status: Constants::Status::NO_MORE_FILES, body: "" }
          end

          # Choose the packing format based on the requested FileInformationClass
          info_class  = request.file_information_class
          pack_method = case info_class
                        when FILE_ID_FULL_DIR_INFO
                          :pack_full_dir_entry
                        when FILE_BOTH_DIR_INFO
                          :pack_entry_no_file_id
                        else
                          # FILE_ID_BOTH_DIR_INFO (0x25) or any unknown → use the richest format
                          :pack_entry
                        end

          # Fixed-portion size per format (used by fix_next_offsets)
          fixed_size = (info_class == FILE_ID_FULL_DIR_INFO) ? 80 : 104

          # Pack entries into the output buffer up to OutputBufferLength
          max_size    = request.output_buffer_length
          output      = "".b
          count       = 0
          single_only = (flags & FLAG_RETURN_SINGLE) != 0

          entries[cursor..].each do |entry|
            packed = send(pack_method, entry)
            # 8-byte align each entry
            padding = (8 - (packed.bytesize % 8)) % 8
            padded  = packed + ("\x00" * padding)

            break if output.bytesize + padded.bytesize > max_size && count > 0

            output += padded
            count  += 1
            open_file.enum_cursor += 1
            break if single_only
          end

          if count == 0
            # Single entry didn't fit — still advance
            open_file.enum_cursor += 1 if cursor < entries.size
          end

          # Fix up NextEntryOffset fields in the packed buffer
          fix_next_offsets(output, fixed_size: fixed_size)

          response = QueryDirectoryResponse.new(
            output_buffer_length: output.bytesize,
            output_buffer:        output
          )
          { status: Constants::Status::SUCCESS, body: response.to_binary_s }
        end

        # ── Private helpers ────────────────────────────────────────────────────

        # Build the complete entry list (. and .. first, then children).
        # Applies a simple wildcard filter (only "*" is fully supported).
        def self.build_entries(open_file, pattern)
          filesystem = open_file.filesystem
          path       = open_file.path

          # Fetch the directory resource for its timestamps
          dir_resource = filesystem.get_resource(path) ||
                         filesystem.get_resource(path.chomp("/"))

          children     = filesystem.list_children(path) || []

          dot_mtime = dir_resource&.last_modified || Time.now
          dot_ctime = dir_resource&.created_at    || Time.now

          entries = []
          entries << { name: ".",  is_dir: true, size: 0, mtime: dot_mtime, ctime: dot_ctime }
          entries << { name: "..", is_dir: true, size: 0, mtime: dot_mtime, ctime: dot_ctime }

          children.each do |child|
            next if skip_entry?(child.path)

            # Strip trailing slash from collection names
            name   = File.basename(child.path.chomp("/"))
            next if name.empty?

            # Apply pattern filter
            next unless matches_pattern?(name, pattern)

            entries << {
              name:  name,
              is_dir: child.collection?,
              size:  child.content_length || 0,
              mtime: child.last_modified,
              ctime: child.created_at
            }
          end

          entries
        end

        # Returns true if the entry path should be skipped (hidden files, etc.)
        def self.skip_entry?(path)
          false  # Show everything for now
        end

        # Match a filename against a simple wildcard pattern.
        # Supports "*" (matches everything) and basic "*.ext" patterns.
        def self.matches_pattern?(name, pattern)
          return true if pattern == "*" || pattern.empty?

          # Convert Windows-style wildcard to Ruby regex
          regex_str = Regexp.escape(pattern).gsub("\\*", ".*").gsub("\\?", ".")
          Regexp.new("\\A#{regex_str}\\z", Regexp::IGNORECASE).match?(name)
        end

        # Pack a single directory entry as FileIdBothDirectoryInformation (0x25).
        #
        # FileIdBothDirectoryInformation structure:
        #   NextEntryOffset (4)    — filled in by fix_next_offsets
        #   FileIndex (4)
        #   CreationTime (8)
        #   LastAccessTime (8)
        #   LastWriteTime (8)
        #   ChangeTime (8)
        #   EndOfFile (8)
        #   AllocationSize (8)
        #   FileAttributes (4)
        #   FileNameLength (4)
        #   EaSize (4)
        #   ShortNameLength (1)
        #   Reserved1 (1)
        #   ShortName (24)
        #   Reserved2 (2)
        #   FileId (8)
        #   FileName (FileNameLength bytes, UTF-16LE)
        #
        # Fixed portion = 4+4+8+8+8+8+8+8+4+4+4+1+1+24+2+8 = 104 bytes
        #
        def self.pack_entry(entry, use_file_id: true)
          name_utf16 = entry[:name].encode("UTF-16LE").b
          attrs      = entry[:is_dir] ? Constants::FileAttributes::DIRECTORY : Constants::FileAttributes::ARCHIVE
          mtime      = time_to_filetime(entry[:mtime])
          ctime      = time_to_filetime(entry[:ctime])
          size       = entry[:size] || 0
          alloc      = entry[:is_dir] ? 0 : ((size + 4095) & ~4095)

          # Build short name (8.3 format, zero-padded to 24 bytes)
          short_name  = generate_short_name(entry[:name])
          short_bytes = short_name.encode("UTF-16LE").b
          short_bytes = short_bytes.ljust(24, "\x00").b[0, 24]

          fixed = [
            0,            # NextEntryOffset (placeholder)
            0,            # FileIndex
            ctime,        # CreationTime
            mtime,        # LastAccessTime
            mtime,        # LastWriteTime
            mtime,        # ChangeTime
            size,         # EndOfFile
            alloc,        # AllocationSize
            attrs,        # FileAttributes
            name_utf16.bytesize, # FileNameLength
            0,            # EaSize
            short_bytes.bytesize / 2,  # ShortNameLength (chars, not bytes)
            0             # Reserved1
          ].pack("L<L<Q<Q<Q<Q<Q<Q<L<L<L<CC")

          fixed += short_bytes
          fixed += [0].pack("S<")   # Reserved2 (2 bytes)
          fixed += [0].pack("Q<")   # FileId (8 bytes) — 0 for simplicity
          fixed += name_utf16

          fixed
        end

        # Generate an 8.3 short name for a given filename.
        # Just truncates base to 8 chars and ext to 3 chars.
        def self.generate_short_name(name)
          ext  = File.extname(name)
          base = File.basename(name, ext)

          short_base = base.upcase.gsub(/[^A-Z0-9_]/, "_")[0, 8]
          short_ext  = ext.sub(".", "").upcase.gsub(/[^A-Z0-9]/, "")[0, 3]

          if short_ext.empty?
            short_base
          else
            "#{short_base}.#{short_ext}"
          end
        end

        # Pack a single directory entry as FileIdFullDirectoryInformation (0x26).
        #
        # FileIdFullDirectoryInformation structure (80-byte fixed portion):
        #   NextEntryOffset (4)
        #   FileIndex (4)
        #   CreationTime (8)
        #   LastAccessTime (8)
        #   LastWriteTime (8)
        #   ChangeTime (8)
        #   EndOfFile (8)
        #   AllocationSize (8)
        #   FileAttributes (4)
        #   FileNameLength (4)
        #   EaSize (4)
        #   Reserved (4)
        #   FileId (8)
        #   FileName (FileNameLength bytes, UTF-16LE)
        #
        def self.pack_full_dir_entry(entry)
          name_utf16 = entry[:name].encode("UTF-16LE").b
          attrs      = entry[:is_dir] ? Constants::FileAttributes::DIRECTORY : Constants::FileAttributes::ARCHIVE
          mtime      = time_to_filetime(entry[:mtime])
          ctime      = time_to_filetime(entry[:ctime])
          size       = entry[:size] || 0
          alloc      = entry[:is_dir] ? 0 : ((size + 4095) & ~4095)

          [
            0,            # NextEntryOffset (placeholder)
            0,            # FileIndex
            ctime,        # CreationTime
            mtime,        # LastAccessTime
            mtime,        # LastWriteTime
            mtime,        # ChangeTime
            size,         # EndOfFile
            alloc,        # AllocationSize
            attrs,        # FileAttributes
            name_utf16.bytesize, # FileNameLength
            0,            # EaSize
            0,            # Reserved
            0             # FileId (8 bytes) — 0 for simplicity
          ].pack("L<L<Q<Q<Q<Q<Q<Q<L<L<L<L<Q<") + name_utf16
        end

        # Pack using FileIdBothDirectoryInformation format but without a FileId
        # (for FILE_BOTH_DIR_INFO = 0x03).
        def self.pack_entry_no_file_id(entry)
          # Delegate to the full pack_entry — both formats have the same layout for our purposes
          pack_entry(entry)
        end

        # Walk through the packed buffer and fix NextEntryOffset for each entry.
        # All entries except the last have NextEntryOffset = bytes to next entry.
        # The last entry has NextEntryOffset = 0.
        #
        # @param fixed_size [Integer] total byte length of fixed header (excluding FileName):
        #   104 for FileIdBothDirectoryInformation, 80 for FileIdFullDirectoryInformation
        def self.fix_next_offsets(buffer, fixed_size: 104)
          # FileNameLength is at byte offset 60 from entry start in all our supported formats.
          # (After NextEntryOffset+FileIndex+4×FILETIMEs+EndOfFile+AllocationSize+FileAttributes
          #  = 4+4+8+8+8+8+8+8+4 = 60 bytes)
          name_len_field_offset = 60

          offset = 0

          while offset < buffer.bytesize
            name_length = buffer[offset + name_len_field_offset, 4].unpack1("L<") rescue 0
            entry_size  = fixed_size + name_length
            padded_size = (entry_size + 7) & ~7

            next_offset = offset + padded_size
            is_last     = next_offset >= buffer.bytesize

            value = is_last ? 0 : padded_size
            buffer[offset, 4] = [value].pack("L<")

            break if is_last
            offset = next_offset
          end

          buffer
        end

        def self.time_to_filetime(time)
          return 0 if time.nil?
          (time.to_i * 10_000_000) + (time.nsec / 100) + Constants::FILETIME_EPOCH_DIFF
        end

        private_class_method :build_entries, :skip_entry?, :matches_pattern?,
                             :pack_entry, :pack_full_dir_entry, :pack_entry_no_file_id,
                             :generate_short_name, :fix_next_offsets, :time_to_filetime
      end
    end
  end
end
