# frozen_string_literal: true

require "bindata"
require "samba_dave/protocol/constants"

module SambaDave
  module Protocol
    # SMB2 Sync Header — 64 bytes, little-endian.
    #
    # Defined in [MS-SMB2] section 2.2.1.1 (SMB2 SYNC Header).
    #
    # Every SMB2 message (request and response) starts with this fixed header.
    # All multi-byte fields are little-endian.
    #
    #   Offset  Size  Field
    #   ──────  ────  ─────
    #    0       4    ProtocolId        0xFE 'S' 'M' 'B'
    #    4       2    StructureSize     Always 64
    #    6       2    CreditCharge      Credits consumed (0 for SMB 2.0.2)
    #    8       4    Status            NT status (0 for requests)
    #   12       2    Command           Command code
    #   14       2    CreditReq/Resp    Credits requested / granted
    #   16       4    Flags             Bit flags
    #   20       4    NextCommand       Offset to next command in compound (0)
    #   24       8    MessageId         Unique message identifier
    #   32       4    Reserved          (or ProcessId for SMB1 compat)
    #   36       4    TreeId            Tree connect identifier
    #   40       8    SessionId         Session identifier
    #   48      16    Signature         Message signature (if signed)
    #
    class Header < BinData::Record
      endian :little

      # Bytes 0-3: Protocol identifier — always 0xFE 'S' 'M' 'B'
      # read_length: 4 — consume 4 bytes from stream; value: fixed output
      string :protocol_id,    read_length: 4, value: "\xFESMB".b

      # Bytes 4-5: Structure size — always 64
      uint16 :structure_size,  value: 64

      # Bytes 6-7: Credit charge (0 for SMB 2.0.2)
      uint16 :credit_charge,   initial_value: 0

      # Bytes 8-11: Status (NT status code; 0 in requests)
      uint32 :status,          initial_value: 0

      # Bytes 12-13: Command code
      uint16 :command,         initial_value: 0

      # Bytes 14-15: Credits requested (client) or granted (server)
      uint16 :credit_request,  initial_value: 0

      # Bytes 16-19: Flags
      uint32 :flags,           initial_value: 0

      # Bytes 20-23: Offset to next command in a compound request (0 = no compound)
      uint32 :next_command,    initial_value: 0

      # Bytes 24-31: Message identifier (monotonically increasing per connection)
      uint64 :message_id,      initial_value: 0

      # Bytes 32-35: Reserved (or process ID in SMB1-compat mode)
      uint32 :reserved,        initial_value: 0

      # Bytes 36-39: Tree connect identifier
      uint32 :tree_id,         initial_value: 0

      # Bytes 40-47: Session identifier
      uint64 :session_id,      initial_value: 0

      # Bytes 48-63: HMAC-SHA256 signature (16 bytes, zero when not signed)
      string :signature,       length: 16, initial_value: "\x00" * 16

      # Build a response header based on an incoming request header.
      #
      # Sets SERVER_TO_REDIR flag and copies message_id, command, session_id, tree_id.
      # Credits are granted generously (128).
      #
      # @param request [Header] the parsed request header
      # @param status [Integer] NT status code for the response
      # @param session_id [Integer, nil] override session_id (nil = copy from request)
      # @param tree_id [Integer, nil] override tree_id (nil = copy from request)
      # @return [Header] a new response header
      def self.response_for(request, status: Constants::Status::SUCCESS, session_id: nil, tree_id: nil)
        new(
          command:        request.command,
          message_id:     request.message_id,
          session_id:     session_id || request.session_id,
          tree_id:        tree_id || request.tree_id,
          flags:          Constants::Flags::SERVER_TO_REDIR,
          status:         status,
          credit_request: 128  # generous credit grant
        )
      end
    end
  end
end
