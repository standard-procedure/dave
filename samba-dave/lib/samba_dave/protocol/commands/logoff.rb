# frozen_string_literal: true

require "bindata"
require "samba_dave/protocol/constants"

module SambaDave
  module Protocol
    module Commands
      # SMB2 LOGOFF Request body (MS-SMB2 section 2.2.21)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize  — always 4
      #  2       2    Reserved       — must be 0
      #
      class LogoffRequest < BinData::Record
        endian :little

        uint16 :structure_size
        uint16 :reserved, initial_value: 0
      end

      # SMB2 LOGOFF Response body (MS-SMB2 section 2.2.22)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize  — always 4
      #  2       2    Reserved       — must be 0
      #
      class LogoffResponse < BinData::Record
        endian :little

        uint16 :structure_size, value: 4
        uint16 :reserved,       initial_value: 0
      end

      # Handles the SMB2 LOGOFF command.
      #
      # Removes the session from the sessions table and returns STATUS_SUCCESS.
      # Per MS-SMB2, LOGOFF always succeeds even if the session is not found.
      #
      module Logoff
        # Handle a LOGOFF request.
        #
        # @param body [String] raw request body bytes
        # @param session_id [Integer] from the SMB2 header
        # @param sessions [Hash] session_id → Session mapping (mutated)
        # @return [Hash] { status: Integer, body: String }
        def self.handle(body, session_id:, sessions:)
          sessions.delete(session_id)

          response = LogoffResponse.new
          { status: Constants::Status::SUCCESS, body: response.to_binary_s }
        end
      end
    end
  end
end
