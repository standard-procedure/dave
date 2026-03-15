# frozen_string_literal: true

require "bindata"
require "samba_dave/protocol/constants"

module SambaDave
  module Protocol
    module Commands
      # SMB2 FLUSH Request body (MS-SMB2 section 2.2.17) — 24 bytes.
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize     — always 24
      #  2       2    Reserved1         — 0
      #  4       4    Reserved2         — 0
      #  8       8    FileId.Persistent
      # 16       8    FileId.Volatile
      #
      class FlushRequest < BinData::Record
        endian :little

        uint16 :structure_size
        uint16 :reserved1,          initial_value: 0
        uint32 :reserved2,          initial_value: 0
        uint64 :file_id_persistent, initial_value: 0
        uint64 :file_id_volatile,   initial_value: 0
      end

      # SMB2 FLUSH Response body (MS-SMB2 section 2.2.18) — 4 bytes.
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize     — always 4
      #  2       2    Reserved          — 0
      #
      class FlushResponse < BinData::Record
        endian :little

        uint16 :structure_size, value: 4
        uint16 :reserved,       initial_value: 0
      end

      # Handles the SMB2 FLUSH command.
      #
      # The Dave filesystem provider is synchronous — writes are committed
      # immediately. FLUSH is therefore a no-op; we validate the FileId and
      # return STATUS_SUCCESS.
      #
      # Error cases:
      #   STATUS_INVALID_HANDLE — FileId not found in open_file_table
      #
      module Flush
        # @param body [String] raw request body (after 64-byte SMB2 header)
        # @param open_file_table [OpenFileTable]
        # @return [Hash] { status: Integer, body: String }
        def self.handle(body, open_file_table:)
          request = FlushRequest.read(body)

          file_id_bytes = [request.file_id_persistent, request.file_id_volatile].pack("Q<Q<")
          open_file     = open_file_table.get(file_id_bytes)

          return { status: Constants::Status::INVALID_HANDLE, body: "" } unless open_file

          { status: Constants::Status::SUCCESS, body: FlushResponse.new.to_binary_s }
        end
      end
    end
  end
end
