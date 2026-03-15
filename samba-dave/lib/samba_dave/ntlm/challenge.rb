# frozen_string_literal: true

require "net/ntlm"
require "openssl"

module SambaDave
  module NTLM
    # Builds NTLM Type2 challenge messages and validates Type3 authenticate messages.
    #
    # ## NTLMv2 Protocol Overview
    #
    # Round 1 (server side):
    #   - Receive Type1 (NEGOTIATE) from client
    #   - Generate 8-byte random server_challenge
    #   - Build and send Type2 (CHALLENGE) wrapping the server_challenge
    #
    # Round 2 (server side):
    #   - Receive Type3 (AUTHENTICATE) from client
    #   - Extract username, NT response (NTProofStr + blob)
    #   - Look up the user's password
    #   - Compute expected NTProofStr using: NTHash, NTLMv2Hash, server_challenge, client_blob
    #   - Compare with received NTProofStr (constant-time) → valid/invalid
    #
    # ## Why We Compute NTLMv2 Manually
    #
    # rubyntlm's `Type3#password?` has a known bug (v0.6.5): the `password`
    # parameter is not used in the NTLMv2 validation path — it always uses an
    # empty string. We implement the validation ourselves using OpenSSL HMAC-MD5.
    #
    module Challenge
      # Build a Type2 (CHALLENGE) NTLM message.
      #
      # @param server_challenge [String] 8 random bytes (the server nonce)
      # @param target_name [String] optional server target name (e.g. "WORKGROUP")
      # @return [String] serialised Type2 binary message
      def self.build(server_challenge:, target_name: "")
        t2 = Net::NTLM::Message::Type2.new

        # Embed the server challenge as a little-endian 64-bit integer value
        # rubyntlm stores challenge as an Int64LE field
        challenge_int = server_challenge.b.unpack1("Q<")
        t2[:challenge].value = challenge_int

        # Must enable target_info to avoid a rubyntlm nil-value bug in deflag
        # (rubyntlm 0.6.5 raises NoMethodError if target_info is inactive but
        # the parser tries to re-activate it during round-trip parsing)
        t2.enable(:target_info)
        t2[:target_info].value = ""

        t2.serialize.b
      end

      # Validate a Type3 (AUTHENTICATE) NTLM message using NTLMv2.
      #
      # Returns the username string if authentication succeeds, nil otherwise.
      #
      # ## NTLMv2 Validation Steps
      #
      #   1. Parse Type3: extract ntlm_response, user (UTF-16LE), domain (UTF-16LE)
      #   2. Split ntlm_response: NTProofStr = first 16 bytes; blob = remainder
      #   3. NTHash = MD4(UTF-16LE(password))  [via Net::NTLM.ntlm_hash]
      #   4. username_upper_utf16 = UTF-16LE(upper(username))
      #   5. NTLMv2Hash = HMAC-MD5(NTHash, username_upper_utf16 + domain_utf16)
      #   6. expected = HMAC-MD5(NTLMv2Hash, server_challenge + blob)
      #   7. Compare expected with NTProofStr
      #
      # @param type3_bytes [String, nil] serialised Type3 binary message
      # @param server_challenge [String] the 8-byte challenge originally sent to client
      # @param password [String] the user's plaintext password from the SecurityProvider
      # @return [String, nil] the username (decoded from UTF-16LE) on success, nil on failure
      def self.validate(type3_bytes, server_challenge:, password:)
        return nil if type3_bytes.nil? || type3_bytes.empty?

        type3 = Net::NTLM::Message.parse(type3_bytes.b)
        return nil unless type3.is_a?(Net::NTLM::Message::Type3)
        return nil unless type3.ntlm_version == :ntlmv2

        validate_ntlmv2(type3, server_challenge, password)
      rescue
        nil
      end

      # ── Private helpers ──────────────────────────────────────────────────────

      # Perform NTLMv2 response validation.
      #
      # @param type3 [Net::NTLM::Message::Type3] parsed Type3 message
      # @param server_challenge [String] 8-byte server nonce
      # @param password [String] plaintext password
      # @return [String, nil] decoded username or nil
      def self.validate_ntlmv2(type3, server_challenge, password)
        nt_response = type3.ntlm_response.b

        # NTProofStr is the first 16 bytes; the NTLMv2 blob follows
        nt_proof_str = nt_response[0, 16]
        client_blob  = nt_response[16..]

        # user and domain fields are UTF-16LE encoded strings
        user_utf16   = type3.user.b
        domain_utf16 = type3.domain.b

        # Step 1: Compute NTHash = MD4(UTF-16LE(password))
        nt_hash = Net::NTLM.ntlm_hash(password)

        # Step 2: Compute NTLMv2Hash = HMAC-MD5(NTHash, UPPER(user_utf16) + domain_utf16)
        # Username must be uppercased: decode from UTF-16LE, upcase, re-encode
        username_str      = Net::NTLM::EncodeUtil.decode_utf16le(user_utf16)
        username_upper    = username_str.upcase
        user_upper_utf16  = Net::NTLM::EncodeUtil.encode_utf16le(username_upper)
        ntlmv2_hash       = OpenSSL::HMAC.digest("MD5", nt_hash, user_upper_utf16 + domain_utf16)

        # Step 3: Compute expected NTProofStr = HMAC-MD5(NTLMv2Hash, server_challenge + blob)
        expected = OpenSSL::HMAC.digest("MD5", ntlmv2_hash, server_challenge.b + client_blob)

        # Step 4: Constant-time comparison
        return nil unless OpenSSL.fixed_length_secure_compare(expected.b, nt_proof_str.b)

        # Return the decoded username on success
        username_str
      rescue
        nil
      end

      private_class_method :validate_ntlmv2
    end
  end
end
