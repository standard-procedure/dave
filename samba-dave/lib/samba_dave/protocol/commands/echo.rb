# frozen_string_literal: true

require "bindata"
require "samba_dave/protocol/constants"

module SambaDave
  module Protocol
    module Commands
      # SMB2 ECHO Request body (MS-SMB2 section 2.2.28)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize  — always 4
      #  2       2    Reserved       — must be 0
      #
      class EchoRequest < BinData::Record
        endian :little

        uint16 :structure_size
        uint16 :reserved, initial_value: 0
      end

      # SMB2 ECHO Response body (MS-SMB2 section 2.2.29)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize  — always 4
      #  2       2    Reserved       — must be 0
      #
      class EchoResponse < BinData::Record
        endian :little

        uint16 :structure_size, value: 4
        uint16 :reserved, initial_value: 0
      end

      # Handles the SMB2 ECHO command.
      #
      # ECHO is a simple keep-alive ping. The server always responds with
      # STATUS_SUCCESS and the minimal 4-byte body.
      #
      module Echo
        # @param body [String] raw request body (ignored — ECHO has no meaningful payload)
        # @return [Hash] { status: Integer, body: String }
        def self.handle(body)
          response = EchoResponse.new
          { status: Constants::Status::SUCCESS, body: response.to_binary_s }
        end
      end
    end
  end
end
