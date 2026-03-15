# frozen_string_literal: true

require "bindata"
require "digest"
require "samba_dave/protocol/constants"

module SambaDave
  module Protocol
    module Commands
      # SMB2 QUERY_INFO Request body (MS-SMB2 section 2.2.37)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize          — always 41
      #  2       1    InfoType               — FILE/FILESYSTEM/SECURITY/QUOTA
      #  3       1    FileInformationClass   — class within InfoType
      #  4       4    OutputBufferLength     — max bytes caller can receive
      #  8       2    InputBufferOffset      — offset from SMB2 header
      # 10       2    Reserved
      # 12       4    InputBufferLength
      # 16       4    AdditionalInformation
      # 20       4    Flags
      # 24       8    FileId.Persistent
      # 32       8    FileId.Volatile
      #
      class QueryInfoRequest < BinData::Record
        endian :little

        uint16 :structure_size
        uint8  :info_type
        uint8  :file_information_class
        uint32 :output_buffer_length
        uint16 :input_buffer_offset
        uint16 :reserved,             initial_value: 0
        uint32 :input_buffer_length
        uint32 :additional_information
        uint32 :flags
        uint64 :file_id_persistent
        uint64 :file_id_volatile
      end

      # SMB2 QUERY_INFO Response body (MS-SMB2 section 2.2.38)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize          — always 9 (includes 1 variable byte)
      #  2       2    OutputBufferOffset     — offset from SMB2 header (64 + 8 = 72)
      #  4       4    OutputBufferLength
      #  8      var   OutputBuffer
      #
      class QueryInfoResponse < BinData::Record
        endian :little

        uint16 :structure_size,       value: 9
        uint16 :output_buffer_offset, initial_value: 72  # 64-byte header + 8-byte fixed response
        uint32 :output_buffer_length, initial_value: 0
        string :output_buffer,        read_length: :output_buffer_length
      end

      # Handles the SMB2 QUERY_INFO command.
      #
      # Queries file metadata (FileBasicInformation, FileStandardInformation,
      # FileNetworkOpenInformation) or filesystem metadata (FileFsVolumeInformation,
      # FileFsSizeInformation) for the given FileId.
      #
      module QueryInfo
        # InfoType constants
        INFO_TYPE_FILE       = 0x01
        INFO_TYPE_FILESYSTEM = 0x02
        INFO_TYPE_SECURITY   = 0x03
        INFO_TYPE_QUOTA      = 0x04

        # FileInformationClass (InfoType=FILE) constants
        FILE_BASIC_INFO             = 0x04  # timestamps + attributes
        FILE_STANDARD_INFO          = 0x05  # size + directory flag
        FILE_INTERNAL_INFO          = 0x06  # index number (inode-like)
        FILE_EA_INFO                = 0x07  # EA size
        FILE_ALL_INFO               = 0x12  # combination
        FILE_NETWORK_OPEN_INFO      = 0x22  # combined timestamps + sizes
        FILE_ATTRIBUTE_TAG_INFO     = 0x23  # FileAttributes + ReparseTag
        FILE_NORMALIZED_NAME_INFO   = 0x30  # Normalized path (not supported)

        # FsInformationClass (InfoType=FILESYSTEM) constants
        FS_VOLUME_INFO    = 0x01  # volume label + serial
        FS_SIZE_INFO      = 0x03  # total/free space
        FS_ATTR_INFO      = 0x05  # FS name + capabilities
        FS_FULL_SIZE_INFO = 0x07  # extended size info

        # @param body [String] raw request body
        # @param open_file_table [OpenFileTable]
        # @return [Hash] { status:, body: }
        def self.handle(body, open_file_table:)
          request = QueryInfoRequest.read(body)

          file_id_bytes = [request.file_id_persistent, request.file_id_volatile].pack("Q<Q<")
          open_file     = open_file_table.get(file_id_bytes)

          return { status: Constants::Status::INVALID_HANDLE, body: "" } unless open_file

          # macOS Finder compatibility: resource forks and metadata never exist
          if macos_probe_path?(open_file.path)
            return { status: Constants::Status::OBJECT_NAME_NOT_FOUND, body: "" }
          end

          case request.info_type
          when INFO_TYPE_FILE
            handle_file_info(request, open_file)
          when INFO_TYPE_FILESYSTEM
            handle_fs_info(request, open_file)
          else
            { status: Constants::Status::INVALID_INFO_CLASS, body: "" }
          end
        end

        # ── Private handlers ──────────────────────────────────────────────────

        def self.handle_file_info(request, open_file)
          resource = open_file.filesystem.get_resource(open_file.path)
          return { status: Constants::Status::OBJECT_NAME_NOT_FOUND, body: "" } unless resource

          case request.file_information_class
          when FILE_BASIC_INFO
            build_response(file_basic_info(resource))

          when FILE_STANDARD_INFO
            build_response(file_standard_info(resource))

          when FILE_NETWORK_OPEN_INFO
            build_response(file_network_open_info(resource))

          when FILE_EA_INFO
            # EA (extended attributes) size — always 0 for our provider
            build_response([0].pack("L<"))

          when FILE_INTERNAL_INFO
            # FileInternalInformation — stable 64-bit index derived from path.
            # Use the first 8 bytes of SHA-256(path) as a deterministic inode-like value.
            index = Digest::SHA256.digest(open_file.path)[0, 8].unpack1("Q<")
            build_response([index].pack("Q<"))

          when FILE_ALL_INFO
            # Combination of multiple info classes — return basic + standard + network-open
            basic    = file_basic_info(resource)
            standard = file_standard_info(resource)
            # FILE_ALL_INFO is complex; return a simplified version
            buf = basic + standard + [0].pack("Q<")  # + EA size
            build_response(buf)

          when FILE_ATTRIBUTE_TAG_INFO
            # FileAttributeTagInformation — FileAttributes(4) + ReparseTag(4)
            # We never create reparse points, so ReparseTag is always 0.
            attrs = resource.collection? ? Constants::FileAttributes::DIRECTORY : Constants::FileAttributes::ARCHIVE
            build_response([attrs, 0].pack("L<L<"))

          when FILE_NORMALIZED_NAME_INFO
            # FileNormalizedNameInformation — not supported. Return INVALID_INFO_CLASS
            # so Windows falls back to using the path it already knows.
            { status: Constants::Status::INVALID_INFO_CLASS, body: "" }

          else
            { status: Constants::Status::INVALID_INFO_CLASS, body: "" }
          end
        end

        def self.handle_fs_info(request, open_file)
          case request.file_information_class
          when FS_VOLUME_INFO
            build_response(fs_volume_info)

          when FS_SIZE_INFO
            build_response(fs_size_info)

          when FS_ATTR_INFO
            build_response(fs_attribute_info)

          when FS_FULL_SIZE_INFO
            build_response(fs_full_size_info)

          else
            { status: Constants::Status::INVALID_INFO_CLASS, body: "" }
          end
        end

        # ── File info structures ───────────────────────────────────────────────

        # FileBasicInformation (0x04) — 40 bytes
        #   CreationTime(8) LastAccessTime(8) LastWriteTime(8) ChangeTime(8)
        #   FileAttributes(4) Reserved(4)
        def self.file_basic_info(resource)
          now   = time_to_filetime(resource.last_modified)
          ctime = time_to_filetime(resource.created_at)
          attrs = resource.collection? ? Constants::FileAttributes::DIRECTORY : Constants::FileAttributes::ARCHIVE
          [ctime, now, now, now, attrs, 0].pack("Q<Q<Q<Q<L<L<")
        end

        # FileStandardInformation (0x05) — 24 bytes
        #   AllocationSize(8) EndOfFile(8) NumberOfLinks(4) DeletePending(1)
        #   Directory(1) Reserved(2)
        def self.file_standard_info(resource)
          size  = resource.content_length || 0
          alloc = (size + 4095) & ~4095
          dir   = resource.collection? ? 1 : 0
          [alloc, size, 1, 0, dir].pack("Q<Q<L<CC") + "\x00\x00"
        end

        # FileNetworkOpenInformation (0x22) — 56 bytes
        #   CreationTime(8) LastAccessTime(8) LastWriteTime(8) ChangeTime(8)
        #   AllocationSize(8) EndOfFile(8) FileAttributes(4) Reserved(4)
        def self.file_network_open_info(resource)
          now   = time_to_filetime(resource.last_modified)
          ctime = time_to_filetime(resource.created_at)
          size  = resource.content_length || 0
          alloc = (size + 4095) & ~4095
          attrs = resource.collection? ? Constants::FileAttributes::DIRECTORY : Constants::FileAttributes::ARCHIVE
          [ctime, now, now, now, alloc, size, attrs, 0].pack("Q<Q<Q<Q<Q<Q<L<L<")
        end

        # ── Filesystem info structures ─────────────────────────────────────────

        # FileFsVolumeInformation (0x01)
        #   VolumeCreationTime(8) VolumeSerialNumber(4) VolumeLabelLength(4)
        #   SupportsObjects(1) Reserved(1) VolumeLabel(var, UTF-16LE)
        def self.fs_volume_info
          label       = "Dave".encode("UTF-16LE").b
          serial      = 0x4441_5645  # "DAVE" as hex
          create_time = time_to_filetime(Time.at(0))

          [create_time, serial, label.bytesize, 0, 0].pack("Q<L<L<CC") + label
        end

        # FileFsSizeInformation (0x03) — 24 bytes
        #   TotalAllocationUnits(8) AvailableAllocationUnits(8)
        #   SectorsPerUnit(4) BytesPerSector(4)
        def self.fs_size_info
          total_units = 1_000_000   # arbitrary large value
          free_units  = 900_000     # 90% free
          [total_units, free_units, 8, 512].pack("Q<Q<L<L<")
        end

        # FileFsAttributeInformation (0x05)
        #   FileSystemAttributes(4) MaximumComponentNameLength(4)
        #   FileSystemNameLength(4) FileSystemName(var, UTF-16LE)
        def self.fs_attribute_info
          name  = "NTFS".encode("UTF-16LE").b
          attrs = 0x00000003  # FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES
          [attrs, 255, name.bytesize].pack("L<L<L<") + name
        end

        # FileFsFullSizeInformation (0x07) — 32 bytes
        #   TotalAllocationUnits(8) CallerAvailableAllocationUnits(8)
        #   ActualAvailableAllocationUnits(8) SectorsPerUnit(4) BytesPerSector(4)
        def self.fs_full_size_info
          total = 1_000_000
          avail = 900_000
          [total, avail, avail, 8, 512].pack("Q<Q<Q<L<L<")
        end

        # ── Helpers ────────────────────────────────────────────────────────────

        def self.build_response(buffer)
          response = QueryInfoResponse.new(
            output_buffer_length: buffer.bytesize,
            output_buffer:        buffer
          )
          { status: Constants::Status::SUCCESS, body: response.to_binary_s }
        end

        def self.time_to_filetime(time)
          return 0 if time.nil?
          (time.to_i * 10_000_000) + (time.nsec / 100) + Constants::FILETIME_EPOCH_DIFF
        end

        # Returns true if the path is a macOS Finder resource fork or metadata file.
        def self.macos_probe_path?(path)
          base = File.basename(path.to_s)
          base.start_with?("._") || base == ".DS_Store"
        end

        private_class_method :handle_file_info, :handle_fs_info,
                             :file_basic_info, :file_standard_info, :file_network_open_info,
                             :fs_volume_info, :fs_size_info, :fs_attribute_info, :fs_full_size_info,
                             :build_response, :time_to_filetime, :macos_probe_path?
      end
    end
  end
end
