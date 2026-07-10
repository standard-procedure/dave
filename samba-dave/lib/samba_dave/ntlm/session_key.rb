# frozen_string_literal: true

require "openssl"

module SambaDave
  module NTLM
    # Derives the NTLMv2 ExportedSessionKey — the key SMB2 uses as its
    # Session.SessionKey (and, for SMB 2.0.2/2.1, directly as the SigningKey).
    #
    # Following MS-NLMP:
    #
    #   SessionBaseKey  = HMAC-MD5(ResponseKeyNT, NTProofStr)   # ResponseKeyNT = NTOWFv2
    #   KeyExchangeKey  = SessionBaseKey                        # (NTLMv2)
    #   ExportedSessionKey =
    #     if NEGOTIATE_KEY_EXCH (and SIGN or SEAL):
    #       RC4(KeyExchangeKey, AUTHENTICATE_MESSAGE.EncryptedRandomSessionKey)
    #     else:
    #       KeyExchangeKey
    #
    # Modern Windows/macOS clients set NEGOTIATE_KEY_EXCH when signing, so the
    # RC4 path is the common case. RC4 is implemented here in pure Ruby because
    # OpenSSL 3.x no longer enables the RC4 cipher by default.
    module SessionKey
      module_function

      # Derive the 16-byte ExportedSessionKey.
      #
      # @param response_key_nt [String] NTOWFv2 = HMAC-MD5(NTHash, upcase(user)+domain)
      # @param nt_proof_str [String] the validated 16-byte NTProofStr
      # @param encrypted_random_session_key [String, nil] Type3 EncryptedRandomSessionKey
      # @param key_exchange [Boolean] whether the client negotiated NEGOTIATE_KEY_EXCH
      # @return [String] 16-byte binary ExportedSessionKey
      def derive_exported_session_key(response_key_nt:, nt_proof_str:, encrypted_random_session_key:, key_exchange:)
        session_base_key = OpenSSL::HMAC.digest("MD5", response_key_nt.b, nt_proof_str.b)

        if key_exchange && encrypted_random_session_key && !encrypted_random_session_key.empty?
          rc4(session_base_key, encrypted_random_session_key.b)
        else
          session_base_key
        end
      end

      # Pure-Ruby RC4 (symmetric: the same call encrypts and decrypts).
      #
      # @param key [String] binary key
      # @param data [String] binary input
      # @return [String] binary output, same length as data
      def rc4(key, data)
        s = (0..255).to_a
        key_bytes = key.b.bytes
        j = 0
        256.times do |i|
          j = (j + s[i] + key_bytes[i % key_bytes.length]) & 0xff
          s[i], s[j] = s[j], s[i]
        end

        i = 0
        j = 0
        out = +"".b
        data.b.each_byte do |byte|
          i = (i + 1) & 0xff
          j = (j + s[i]) & 0xff
          s[i], s[j] = s[j], s[i]
          out << (byte ^ s[(s[i] + s[j]) & 0xff]).chr
        end
        out
      end
    end
  end
end
