# frozen_string_literal: true

require "bindata"
require "samba_dave/protocol/constants"

module SambaDave
  module Protocol
    module Commands
      # SMB2 CLOSE Request body (MS-SMB2 section 2.2.15)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize    — always 24
      #  2       2    Flags            — 0x0001 = POSTQUERY_ATTRIB
      #  4       4    Reserved         — 0
      #  8       8    FileId.Persistent
      # 16       8    FileId.Volatile
      #
      class CloseRequest < BinData::Record
        endian :little

        uint16 :structure_size
        uint16 :flags,             initial_value: 0
        uint32 :reserved,          initial_value: 0
        uint64 :file_id_persistent, initial_value: 0
        uint64 :file_id_volatile,   initial_value: 0
      end

      # SMB2 CLOSE Response body (MS-SMB2 section 2.2.16)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize    — always 60
      #  2       2    Flags            — echoed back
      #  4       4    Reserved         — 0
      #  8       8    CreationTime     — FILETIME (or 0 if no POSTQUERY_ATTRIB)
      # 16       8    LastAccessTime
      # 24       8    LastWriteTime
      # 32       8    ChangeTime
      # 40       8    AllocationSize
      # 48       8    EndOfFile
      # 56       4    FileAttributes
      #
      class CloseResponse < BinData::Record
        endian :little

        uint16 :structure_size,  value: 60
        uint16 :flags,           initial_value: 0
        uint32 :reserved,        initial_value: 0
        uint64 :creation_time,   initial_value: 0
        uint64 :last_access_time, initial_value: 0
        uint64 :last_write_time, initial_value: 0
        uint64 :change_time,     initial_value: 0
        uint64 :allocation_size, initial_value: 0
        uint64 :end_of_file,     initial_value: 0
        uint32 :file_attributes, initial_value: 0
      end

      # Handles the SMB2 CLOSE command.
      #
      # Removes the FileId from the OpenFileTable. If the POSTQUERY_ATTRIB
      # flag is set, also queries and returns file metadata from the filesystem.
      #
      module Close
        CLOSE_FLAG_POSTQUERY_ATTRIB = 0x0001

        # @param body [String] raw request body
        # @param open_file_table [OpenFileTable] connection-scoped handle table
        # @return [Hash] { status: Integer, body: String }
        def self.handle(body, open_file_table:)
          request = CloseRequest.read(body)

          # Reconstruct 16-byte FileId from the two uint64 halves
          file_id_bytes = [request.file_id_persistent, request.file_id_volatile].pack("Q<Q<")

          open_file = open_file_table.get(file_id_bytes)
          unless open_file
            return { status: Constants::Status::INVALID_HANDLE, body: build_empty_response(0) }
          end

          open_file_table.remove(file_id_bytes)

          # If delete-on-close was requested, delete the resource now.
          if open_file.delete_on_close
            begin
              open_file.filesystem.delete(open_file.path)
            rescue => _e
              # Silently ignore — handle is already removed
            end
          end

          # Build response — optionally include file metadata
          if (request.flags & CLOSE_FLAG_POSTQUERY_ATTRIB) != 0
            build_postquery_response(open_file)
          else
            { status: Constants::Status::SUCCESS, body: build_empty_response(request.flags) }
          end
        end

        private

        def self.build_empty_response(flags)
          CloseResponse.new(flags: flags).to_binary_s
        end

        def self.build_postquery_response(open_file)
          resource = open_file.filesystem.get_resource(open_file.path)
          if resource.nil?
            return { status: Constants::Status::SUCCESS, body: build_empty_response(CLOSE_FLAG_POSTQUERY_ATTRIB) }
          end

          now    = time_to_filetime(resource.last_modified)
          ctime  = time_to_filetime(resource.created_at)
          size   = resource.content_length || 0
          attrs  = resource.collection? ? Constants::FileAttributes::DIRECTORY : Constants::FileAttributes::ARCHIVE

          response = CloseResponse.new(
            flags:            CLOSE_FLAG_POSTQUERY_ATTRIB,
            creation_time:    ctime,
            last_access_time: now,
            last_write_time:  now,
            change_time:      now,
            allocation_size:  (size + 4095) & ~4095,
            end_of_file:      size,
            file_attributes:  attrs
          )
          { status: Constants::Status::SUCCESS, body: response.to_binary_s }
        end

        def self.time_to_filetime(time)
          return 0 if time.nil?
          (time.to_i * 10_000_000) + (time.nsec / 100) + Constants::FILETIME_EPOCH_DIFF
        end

        private_class_method :build_empty_response, :build_postquery_response, :time_to_filetime
      end
    end
  end
end
