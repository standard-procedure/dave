# frozen_string_literal: true

require "bindata"
require "stringio"
require "samba_dave/protocol/constants"

module SambaDave
  module Protocol
    module Commands
      # SMB2 SET_INFO Request body (MS-SMB2 section 2.2.39) — 32 bytes fixed + variable buffer.
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize         — always 33
      #  2       1    InfoType              — 1=FILE, 2=FILESYSTEM, 3=SECURITY, 4=QUOTA
      #  3       1    FileInformationClass
      #  4       4    BufferLength
      #  8       2    BufferOffset          — offset of buffer from SMB2 header start
      # 10       2    Reserved              — 0
      # 12       4    AdditionalInformation
      # 16       8    FileId.Persistent
      # 24       8    FileId.Volatile
      # 32      var   Buffer
      #
      class SetInfoRequest < BinData::Record
        endian :little

        uint16 :structure_size
        uint8  :info_type
        uint8  :file_information_class
        uint32 :buffer_length
        uint16 :buffer_offset
        uint16 :reserved,              initial_value: 0
        uint32 :additional_information, initial_value: 0
        uint64 :file_id_persistent,    initial_value: 0
        uint64 :file_id_volatile,      initial_value: 0
      end

      # SMB2 SET_INFO Response body (MS-SMB2 section 2.2.40) — 2 bytes.
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize  — always 2
      #
      class SetInfoResponse < BinData::Record
        endian :little

        uint16 :structure_size, value: 2
      end

      # Handles the SMB2 SET_INFO command.
      #
      # Supported FileInformationClass values (InfoType=FILE):
      #   0x04  FileBasicInformation        — timestamps/attributes (no-op)
      #   0x0A  FileRenameInformation       — rename/move via provider.move
      #   0x0D  FileDispositionInformation  — set/clear delete-on-close flag
      #   0x13  FileAllocationInformation   — treat as truncate/extend
      #   0x14  FileEndOfFileInformation    — truncate/extend file
      #
      # All other InfoType values or unsupported classes → STATUS_INVALID_INFO_CLASS.
      #
      module SetInfo
        SMB_HEADER_SIZE = 64

        # InfoType constants
        INFO_TYPE_FILE = 0x01

        # FileInformationClass constants
        FILE_BASIC_INFO        = 0x04
        FILE_RENAME_INFO       = 0x0A
        FILE_DISPOSITION_INFO  = 0x0D
        FILE_ALLOCATION_INFO   = 0x13
        FILE_END_OF_FILE_INFO  = 0x14

        # @param body [String] raw request body (after 64-byte SMB2 header)
        # @param open_file_table [OpenFileTable]
        # @return [Hash] { status: Integer, body: String }
        def self.handle(body, open_file_table:)
          request = SetInfoRequest.read(body)

          file_id_bytes = [request.file_id_persistent, request.file_id_volatile].pack("Q<Q<")
          open_file     = open_file_table.get(file_id_bytes)

          return { status: Constants::Status::INVALID_HANDLE, body: "" } unless open_file

          # Extract the info buffer
          buf_start = request.buffer_offset - SMB_HEADER_SIZE
          buffer    = body.b[buf_start, request.buffer_length] || "".b

          unless request.info_type == INFO_TYPE_FILE
            return { status: Constants::Status::INVALID_INFO_CLASS, body: "" }
          end

          case request.file_information_class
          when FILE_BASIC_INFO
            handle_basic_info(open_file, buffer)
          when FILE_RENAME_INFO
            handle_rename(open_file, buffer)
          when FILE_DISPOSITION_INFO
            handle_disposition(open_file, buffer)
          when FILE_END_OF_FILE_INFO, FILE_ALLOCATION_INFO
            handle_end_of_file(open_file, buffer)
          else
            { status: Constants::Status::INVALID_INFO_CLASS, body: "" }
          end
        end

        # ── Private handlers ───────────────────────────────────────────────────

        # FileBasicInformation — timestamps and attributes.
        # The provider is the source of truth for timestamps; we accept and ignore.
        def self.handle_basic_info(_open_file, _buffer)
          success_response
        end

        # FileRenameInformation — rename/move the file via provider.move.
        #
        # Structure (64-bit variant as used by SMB2):
        #   ReplaceIfExists (1)  Reserved (7)  RootDirectory (8)
        #   FileNameLength (4)   FileName (var, UTF-16LE)
        def self.handle_rename(open_file, buffer)
          return { status: Constants::Status::INVALID_PARAMETER, body: "" } if buffer.bytesize < 20

          # Parse: skip ReplaceIfExists(1) + Reserved(7) + RootDirectory(8) = 16 bytes
          name_length = buffer[16, 4].unpack1("L<")
          return { status: Constants::Status::INVALID_PARAMETER, body: "" } if buffer.bytesize < 20 + name_length

          name_bytes = buffer[20, name_length]
          new_name   = name_bytes.force_encoding("UTF-16LE").encode("UTF-8", invalid: :replace, undef: :replace)

          # Normalise: backslash → forward slash, ensure leading "/"
          new_path = new_name.gsub("\\", "/")
          new_path = "/" + new_path unless new_path.start_with?("/")

          begin
            open_file.filesystem.move(open_file.path, new_path)
            success_response
          rescue Dave::NotFoundError
            { status: Constants::Status::OBJECT_NAME_NOT_FOUND, body: "" }
          rescue Dave::AlreadyExistsError
            { status: Constants::Status::OBJECT_NAME_COLLISION, body: "" }
          rescue => _e
            { status: Constants::Status::ACCESS_DENIED, body: "" }
          end
        end

        # FileDispositionInformation — set or clear the delete-on-close flag.
        #
        # Structure: DeletePending (1 byte) — 0=clear, non-zero=set
        def self.handle_disposition(open_file, buffer)
          return { status: Constants::Status::INVALID_PARAMETER, body: "" } if buffer.bytesize < 1

          open_file.delete_on_close = buffer[0].ord != 0
          success_response
        end

        # FileEndOfFileInformation / FileAllocationInformation — resize the file.
        #
        # Structure: EndOfFile/AllocationSize (8 bytes, int64)
        def self.handle_end_of_file(open_file, buffer)
          return { status: Constants::Status::INVALID_PARAMETER, body: "" } if buffer.bytesize < 8

          new_size   = buffer[0, 8].unpack1("q<")  # signed int64
          new_size   = [new_size, 0].max            # clamp to non-negative

          filesystem = open_file.filesystem

          # Read existing content
          existing = begin
            io = filesystem.read_content(open_file.path)
            content = io.read.b
            io.close
            content
          rescue Dave::NotFoundError
            "".b
          end

          resized = if new_size <= existing.bytesize
            existing[0, new_size]
          else
            existing + ("\x00".b * (new_size - existing.bytesize))
          end

          filesystem.write_content(open_file.path, StringIO.new(resized))
          success_response
        rescue => _e
          { status: Constants::Status::ACCESS_DENIED, body: "" }
        end

        def self.success_response
          { status: Constants::Status::SUCCESS, body: SetInfoResponse.new.to_binary_s }
        end

        private_class_method :handle_basic_info, :handle_rename, :handle_disposition,
                             :handle_end_of_file, :success_response
      end
    end
  end
end
