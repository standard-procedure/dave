# frozen_string_literal: true

require "securerandom"
require "samba_dave/ntlm/spnego"
require "samba_dave/ntlm/challenge"
require "samba_dave/security_provider"

module SambaDave
  # Bridges the NTLM challenge-response protocol to the SecurityProvider.
  #
  # One Authenticator is shared across a Connection. It tracks in-progress
  # NTLM handshakes (by session_id) and validates the final Type3 response.
  #
  # ## Two-round NTLM handshake
  #
  # **Round 1** — `begin_auth(session_id, security_buffer)`:
  #   - Extracts NTLM Type1 from the SPNEGO-wrapped security buffer
  #   - Generates an 8-byte server challenge
  #   - Builds a Type2 (CHALLENGE) message and SPNEGO-wraps it
  #   - Stores the server challenge keyed by session_id
  #   - Returns the SPNEGO-wrapped Type2 bytes
  #
  # **Round 2** — `complete_auth(session_id, security_buffer)`:
  #   - Extracts NTLM Type3 from the SPNEGO-wrapped security buffer
  #   - Retrieves the stored server challenge for this session
  #   - Extracts username from Type3, looks up the password via SecurityProvider
  #   - Validates the NTLMv2 response (HMAC-MD5 chain)
  #   - If valid: calls `provider.authenticate` and returns the user identity
  #   - If invalid: returns nil
  #
  class Authenticator
    # @param security_provider [SecurityProvider] the app's credential store
    def initialize(security_provider)
      @provider  = security_provider
      @pending   = {}  # session_id → { challenge: bytes, timestamp: Time }
      @mutex     = Mutex.new
    end

    # Begin NTLM authentication (Round 1).
    #
    # @param session_id [Integer] the SMB2 session identifier
    # @param security_buffer [String] SPNEGO/NTLM security buffer from CLIENT SESSION_SETUP request
    # @return [String] SPNEGO-wrapped Type2 challenge to send to client
    def begin_auth(session_id, security_buffer)
      # We don't actually need to parse Type1 for app-password NTLM —
      # just generate a challenge and send Type2.
      server_challenge = SecureRandom.bytes(8)

      @mutex.synchronize do
        @pending[session_id] = { challenge: server_challenge, timestamp: Time.now }
      end

      type2_bytes = NTLM::Challenge.build(server_challenge: server_challenge)
      NTLM::SPNEGO.wrap_challenge(type2_bytes)
    end

    # Complete NTLM authentication (Round 2).
    #
    # @param session_id [Integer] the SMB2 session identifier
    # @param security_buffer [String] SPNEGO/NTLM security buffer from CLIENT SESSION_SETUP request
    # @return [Object, nil] user identity on success, nil on failure
    def complete_auth(session_id, security_buffer)
      pending = @mutex.synchronize { @pending.delete(session_id) }
      return nil unless pending

      server_challenge = pending[:challenge]

      # Unwrap SPNEGO to get raw NTLM Type3 bytes
      type3_bytes = NTLM::SPNEGO.unwrap(security_buffer)
      return nil unless type3_bytes

      # Validate Type3 and extract username
      username = NTLM::Challenge.validate(
        type3_bytes,
        server_challenge: server_challenge,
        password: @provider.credential_for(extract_username_from_type3(type3_bytes))
      )
      return nil unless username

      # Retrieve password and call provider.authenticate for the identity
      password = @provider.credential_for(username)
      return nil unless password

      @provider.authenticate(username, password)
    end

    # @return [Boolean] true if a pending challenge exists for this session
    def pending_challenge?(session_id)
      @mutex.synchronize { @pending.key?(session_id) }
    end

    private

    # Extract the username from a raw Type3 message without full validation.
    # Returns nil if parsing fails.
    def extract_username_from_type3(type3_bytes)
      type3 = Net::NTLM::Message.parse(type3_bytes.b)
      return nil unless type3.is_a?(Net::NTLM::Message::Type3)

      user_utf16 = type3.user.b
      return nil if user_utf16.empty?

      Net::NTLM::EncodeUtil.decode_utf16le(user_utf16)
    rescue
      nil
    end
  end
end
