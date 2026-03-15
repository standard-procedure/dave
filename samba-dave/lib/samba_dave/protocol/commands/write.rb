# frozen_string_literal: true

require "bindata"
require "stringio"
require "samba_dave/protocol/constants"

module SambaDave
  module Protocol
    module Commands
      # SMB2 WRITE Request body (MS-SMB2 section 2.2.21) — 48 bytes fixed + variable data.
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize           — always 49 (includes 1 variable byte)
      #  2       2    DataOffset              — offset of data from start of SMB2 header (≥ 112)
      #  4       4    Length                  — bytes to write (write_count)
      #  8       8    Offset                  — file offset
      # 16       8    FileId.Persistent
      # 24       8    FileId.Volatile
      # 32       4    Channel                 — 0
      # 36       4    RemainingBytes          — 0
      # 40       2    WriteChannelInfoOffset  — 0
      # 42       2    WriteChannelInfoLength  — 0
      # 44       4    Flags                   — 0
      # 48      var   Buffer                  — data to write
      #
      # Note: 'length' is reserved in BinData; we use write_count.
      #
      class WriteRequest < BinData::Record
        endian :little

        uint16 :structure_size
        uint16 :data_offset
        uint32 :write_count
        uint64 :offset
        uint64 :file_id_persistent,          initial_value: 0
        uint64 :file_id_volatile,            initial_value: 0
        uint32 :channel,                     initial_value: 0
        uint32 :remaining_bytes,             initial_value: 0
        uint16 :write_channel_info_offset,   initial_value: 0
        uint16 :write_channel_info_length,   initial_value: 0
        uint32 :flags,                       initial_value: 0
      end

      # SMB2 WRITE Response body (MS-SMB2 section 2.2.22) — 16 bytes.
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize           — always 17 (includes 1 variable byte)
      #  2       2    Reserved                — 0
      #  4       4    Count                   — bytes written
      #  8       4    Remaining               — 0
      # 12       2    WriteChannelInfoOffset  — 0
      # 14       2    WriteChannelInfoLength  — 0
      #
      class WriteResponse < BinData::Record
        endian :little

        uint16 :structure_size,              value: 17
        uint16 :reserved,                    initial_value: 0
        uint32 :bytes_written,               initial_value: 0
        uint32 :remaining,                   initial_value: 0
        uint16 :write_channel_info_offset,   initial_value: 0
        uint16 :write_channel_info_length,   initial_value: 0
      end

      # Handles the SMB2 WRITE command.
      #
      # Writes data into the file at the specified offset. Because the provider
      # interface is stateless (write_content replaces the whole file), we:
      #   1. Read the existing file content
      #   2. Extend the buffer if the write extends beyond the current end
      #   3. Splice the new data in at the given offset
      #   4. Write the entire buffer back via write_content
      #
      # Error cases:
      #   STATUS_INVALID_HANDLE    — FileId not found in open_file_table
      #   STATUS_INVALID_PARAMETER — handle refers to a directory
      #
      module Write
        SMB_HEADER_SIZE = 64

        # @param body [String] raw request body (after 64-byte SMB2 header)
        # @param open_file_table [OpenFileTable]
        # @return [Hash] { status: Integer, body: String }
        def self.handle(body, open_file_table:)
          request = WriteRequest.read(body)

          file_id_bytes = [request.file_id_persistent, request.file_id_volatile].pack("Q<Q<")
          open_file     = open_file_table.get(file_id_bytes)

          return { status: Constants::Status::INVALID_HANDLE, body: "" } unless open_file

          if open_file.directory?
            return { status: Constants::Status::INVALID_PARAMETER, body: "" }
          end

          # Extract the data buffer from the body
          data_start = request.data_offset - SMB_HEADER_SIZE
          data       = body.b[data_start, request.write_count] || "".b

          write_data(open_file, request.offset, data)
        end

        # ── Private ────────────────────────────────────────────────────────────

        # Splice `data` at `offset` into the file and write the full content back.
        def self.write_data(open_file, offset, data)
          filesystem = open_file.filesystem

          # Read existing content (empty if file doesn't exist yet)
          existing = begin
            io = filesystem.read_content(open_file.path)
            content = io.read
            io.close
            content.b
          rescue Dave::NotFoundError
            "".b
          end

          # Calculate new file size
          end_pos  = offset + data.bytesize
          new_size = [existing.bytesize, end_pos].max

          # Build buffer: extend with zero bytes if needed
          buf = existing.ljust(new_size, "\x00".b)

          # Splice in the new data
          buf[offset, data.bytesize] = data.b

          filesystem.write_content(open_file.path, StringIO.new(buf))

          response = WriteResponse.new(bytes_written: data.bytesize)
          { status: Constants::Status::SUCCESS, body: response.to_binary_s }
        rescue => _e
          { status: Constants::Status::ACCESS_DENIED, body: "" }
        end

        private_class_method :write_data
      end
    end
  end
end
