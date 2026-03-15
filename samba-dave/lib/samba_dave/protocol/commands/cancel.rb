# frozen_string_literal: true

require "bindata"
require "samba_dave/protocol/constants"

module SambaDave
  module Protocol
    module Commands
      # SMB2 CANCEL Request body (MS-SMB2 section 2.2.30) — 4 bytes.
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize  — always 4
      #  2       2    Reserved       — 0
      #
      # The request to cancel is identified by the MessageId (or AsyncId for
      # async commands) in the SMB2 header of this CANCEL message.
      #
      class CancelRequest < BinData::Record
        endian :little

        uint16 :structure_size
        uint16 :reserved, initial_value: 0
      end

      # Handles the SMB2 CANCEL command.
      #
      # Per MS-SMB2 section 3.3.5.15, the server MUST NOT send a response to
      # the CANCEL request itself. If a pending request matches the MessageId
      # (or AsyncId), that request is completed with STATUS_CANCELLED.
      #
      # Since samba-dave is synchronous (no pending async requests), there is
      # never anything to cancel. We simply return a sentinel hash that
      # instructs the connection layer to suppress any response.
      #
      module Cancel
        # @param body [String] raw request body (after 64-byte SMB2 header)
        # @return [Hash] { skip_response: true, status: nil, body: nil }
        def self.handle(body)
          # Parse the body to validate it (raises if malformed)
          CancelRequest.read(body)
          # Signal to the connection layer: do NOT send a response.
          { skip_response: true, status: nil, body: nil }
        end
      end
    end
  end
end
