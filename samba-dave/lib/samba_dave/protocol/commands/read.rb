# frozen_string_literal: true

require "bindata"
require "samba_dave/protocol/constants"

module SambaDave
  module Protocol
    module Commands
      # SMB2 READ Request body (MS-SMB2 section 2.2.19) — 49 bytes total.
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize     — always 49
      #  2       1    Padding           — 0
      #  3       1    Flags             — SMB 3.x only
      #  4       4    Length (read_count) — bytes to read
      #  8       8    Offset            — file offset
      # 16       8    FileId.Persistent
      # 24       8    FileId.Volatile
      # 32       4    MinimumCount
      # 36       4    Channel           — 0
      # 40       4    RemainingBytes    — 0
      # 44       2    ReadChannelInfoOffset
      # 46       2    ReadChannelInfoLength
      # 48       1    Buffer            — padding byte
      #
      class ReadRequest < BinData::Record
        endian :little

        uint16 :structure_size
        uint8  :padding,                   initial_value: 0
        uint8  :flags,                     initial_value: 0
        uint32 :read_count
        uint64 :offset
        uint64 :file_id_persistent,        initial_value: 0
        uint64 :file_id_volatile,          initial_value: 0
        uint32 :minimum_count,             initial_value: 0
        uint32 :channel,                   initial_value: 0
        uint32 :remaining_bytes,           initial_value: 0
        uint16 :read_channel_info_offset,  initial_value: 0
        uint16 :read_channel_info_length,  initial_value: 0
      end

      # SMB2 READ Response body (MS-SMB2 section 2.2.20).
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize     — always 17 (includes 1 variable byte)
      #  2       1    DataOffset        — offset to data from SMB2 header start (= 80)
      #  3       1    Reserved          — 0
      #  4       4    DataLength        — bytes of data returned
      #  8       4    DataRemaining     — 0
      # 12       4    Reserved2         — 0
      # 16      var   Buffer            — file data
      #
      class ReadResponse < BinData::Record
        endian :little

        uint16 :structure_size,  value: 17
        uint8  :data_offset,     initial_value: 80  # 64-byte header + 16-byte fixed response
        uint8  :reserved,        initial_value: 0
        uint32 :data_length,     initial_value: 0
        uint32 :data_remaining,  initial_value: 0
        uint32 :reserved2,       initial_value: 0
        string :buffer,          read_length: :data_length
      end

      # Handles the SMB2 READ command.
      #
      # Reads file data at the specified offset and length from the filesystem
      # provider via the OpenFile handle.
      #
      # Error cases:
      #   STATUS_INVALID_HANDLE    — FileId not found in open_file_table
      #   STATUS_INVALID_PARAMETER — handle refers to a directory
      #   STATUS_END_OF_FILE       — offset is at or past end of file
      #
      module Read
        # @param body [String] raw request body (after 64-byte SMB2 header)
        # @param open_file_table [OpenFileTable]
        # @return [Hash] { status: Integer, body: String }
        def self.handle(body, open_file_table:)
          request = ReadRequest.read(body)

          file_id_bytes = [request.file_id_persistent, request.file_id_volatile].pack("Q<Q<")
          open_file     = open_file_table.get(file_id_bytes)

          return { status: Constants::Status::INVALID_HANDLE, body: "" } unless open_file

          if open_file.directory?
            return { status: Constants::Status::INVALID_PARAMETER, body: "" }
          end

          read_data(open_file, request.offset, request.read_count)
        end

        # ── Private ────────────────────────────────────────────────────────────

        # Read `length` bytes at `offset` from the open file's filesystem.
        def self.read_data(open_file, offset, length)
          io   = open_file.filesystem.read_content(open_file.path)
          io.seek(offset)
          data = io.read(length) || ""
          io.close

          if data.empty? && length > 0
            return { status: Constants::Status::END_OF_FILE, body: "" }
          end

          response = ReadResponse.new(
            data_length: data.bytesize,
            buffer:      data
          )
          { status: Constants::Status::SUCCESS, body: response.to_binary_s }
        rescue Dave::NotFoundError
          { status: Constants::Status::OBJECT_NAME_NOT_FOUND, body: "" }
        end

        private_class_method :read_data
      end
    end
  end
end
