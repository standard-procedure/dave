# frozen_string_literal: true

require "bindata"
require "samba_dave/protocol/constants"
require "samba_dave/session"

module SambaDave
  module Protocol
    module Commands
      # SMB2 SESSION_SETUP Request body (MS-SMB2 section 2.2.19)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize             — always 25
      #  2       1    Flags                     — 0 or BINDING(0x01)
      #  3       1    SecurityMode              — signing enabled/required
      #  4       4    Capabilities
      #  8       4    Channel                   — always 0
      # 12       2    SecurityBufferOffset      — from start of SMB2 message
      # 14       2    SecurityBufferLength
      # 16       8    PreviousSessionId         — 0 for new sessions
      # 24     var    SecurityBuffer
      #
      class SessionSetupRequest < BinData::Record
        endian :little

        uint16 :structure_size
        uint8  :flags
        uint8  :security_mode
        uint32 :capabilities
        uint32 :channel,               initial_value: 0
        uint16 :security_buffer_offset
        uint16 :security_buffer_length
        uint64 :previous_session_id,   initial_value: 0
        string :security_buffer,       read_length: :security_buffer_length
      end

      # SMB2 SESSION_SETUP Response body (MS-SMB2 section 2.2.20)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize             — always 9
      #  2       2    SessionFlags              — 0 (or ENCRYPT_DATA for SMB3)
      #  4       2    SecurityBufferOffset      — from start of SMB2 message
      #  6       2    SecurityBufferLength
      #  8     var    SecurityBuffer
      #
      class SessionSetupResponse < BinData::Record
        endian :little

        uint16 :structure_size,            value: 9
        uint16 :session_flags,             initial_value: 0
        uint16 :security_buffer_offset,    initial_value: 72   # 64 (header) + 8 (fixed body)
        uint16 :security_buffer_length,    initial_value: 0
        string :security_buffer,           read_length: :security_buffer_length
      end

      # Handles the SMB2 SESSION_SETUP command.
      #
      # SESSION_SETUP is a two-round handshake:
      #
      #   Round 1: Client sends NTLM Type1 (NEGOTIATE_MESSAGE) wrapped in SPNEGO.
      #            Server responds with Status=MORE_PROCESSING_REQUIRED and a
      #            SPNEGO-wrapped NTLM Type2 (CHALLENGE_MESSAGE).
      #
      #   Round 2: Client sends NTLM Type3 (AUTHENTICATE_MESSAGE) wrapped in SPNEGO.
      #            Server validates the NTLMv2 response and responds with:
      #              - Status=SUCCESS + creates Session → authenticated
      #              - Status=LOGON_FAILURE → rejected
      #
      # The authenticator tracks per-session challenge state between rounds.
      # The sessions hash maps session_id → Session (created on successful Round 2).
      #
      module SessionSetup
        # Security buffer offset: 64-byte SMB2 header + 8-byte fixed SESSION_SETUP response body
        SECURITY_BUFFER_OFFSET = 72

        # Handle a SESSION_SETUP request body.
        #
        # @param body [String] raw request body bytes (after the 64-byte header)
        # @param session_id [Integer] from the SMB2 header (may be 0 for Round 1)
        # @param authenticator [Authenticator] the connection's authenticator
        # @param sessions [Hash] session_id → Session mapping (mutated on success)
        # @return [Hash] { status: Integer, body: String }
        def self.handle(body, session_id:, authenticator:, sessions:)
          request = SessionSetupRequest.read(body)
          security_buffer = request.security_buffer.b

          if authenticator.pending_challenge?(session_id)
            # Round 2: client is sending Type3 AUTHENTICATE
            handle_round2(session_id, security_buffer, authenticator, sessions)
          else
            # Round 1: client is sending Type1 NEGOTIATE (or first-time)
            handle_round1(session_id, security_buffer, authenticator)
          end
        rescue => e
          { status: Constants::Status::INVALID_PARAMETER, body: empty_response }
        end

        # ── Private ──────────────────────────────────────────────────────────────

        def self.handle_round1(session_id, security_buffer, authenticator)
          # begin_auth generates server challenge and returns SPNEGO-wrapped Type2
          type2_spnego = authenticator.begin_auth(session_id, security_buffer)

          response = SessionSetupResponse.new(
            session_flags:          0,
            security_buffer_offset: SECURITY_BUFFER_OFFSET,
            security_buffer_length: type2_spnego.bytesize,
            security_buffer:        type2_spnego
          )

          {
            status: Constants::Status::MORE_PROCESSING_REQUIRED,
            body:   response.to_binary_s
          }
        end

        def self.handle_round2(session_id, security_buffer, authenticator, sessions)
          identity = authenticator.complete_auth(session_id, security_buffer)

          if identity
            # Authentication succeeded — create the session
            session = Session.new(session_id: session_id)
            session.authenticate!(identity)
            sessions[session_id] = session

            response = SessionSetupResponse.new(
              session_flags:          0,
              security_buffer_offset: SECURITY_BUFFER_OFFSET,
              security_buffer_length: 0,
              security_buffer:        ""
            )

            { status: Constants::Status::SUCCESS, body: response.to_binary_s }
          else
            # Authentication failed
            { status: Constants::Status::LOGON_FAILURE, body: empty_response }
          end
        end

        def self.empty_response
          SessionSetupResponse.new(
            security_buffer_offset: SECURITY_BUFFER_OFFSET,
            security_buffer_length: 0,
            security_buffer:        ""
          ).to_binary_s
        end

        private_class_method :handle_round1, :handle_round2, :empty_response
      end
    end
  end
end
