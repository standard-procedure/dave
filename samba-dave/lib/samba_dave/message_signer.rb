# frozen_string_literal: true

require "openssl"

module SambaDave
  # SMB2 message signing and verification using HMAC-SHA256.
  #
  # ## Signing Key Derivation (SMB 2.1)
  #
  # The signing key is derived from the NTLM session base key:
  #
  #   SigningKey = HMAC-SHA256(SessionBaseKey, "SMBSigningKey\x00")
  #
  # This follows a simplified SP800-108 KDF pattern for SMB 2.1.
  #
  # ## Signature Computation
  #
  # The signature covers the entire SMB2 message (header + body) with the
  # 16-byte Signature field (header bytes 48-63) zeroed out:
  #
  #   Signature = HMAC-SHA256(SigningKey, message_with_zeroed_signature)[0, 16]
  #
  # ## Wire format
  #
  # When a response is signed:
  # - The Flags field has SMB2_FLAGS_SIGNED (0x00000008) set
  # - The Signature field contains the 16-byte HMAC-SHA256 truncated result
  #
  module MessageSigner
    # Label used for signing key derivation
    SIGNING_KEY_LABEL = "SMBSigningKey\x00".b.freeze

    # Offset of the Signature field in the SMB2 header (bytes 48-63)
    SIGNATURE_OFFSET = 48
    SIGNATURE_LENGTH = 16

    # Derive the signing key from the NTLM session base key.
    #
    # @param session_key [String] 16-byte NTLM session base key (binary)
    # @return [String] 32-byte HMAC-SHA256 signing key (binary)
    def self.derive_signing_key(session_key)
      OpenSSL::HMAC.digest("SHA256", session_key.b, SIGNING_KEY_LABEL)
    end

    # Compute the 16-byte HMAC-SHA256 signature for an SMB2 message.
    #
    # The signature field in the message is zeroed before computing the HMAC.
    # The result is the first 16 bytes of the HMAC-SHA256 output.
    #
    # @param signing_key [String] signing key (from derive_signing_key)
    # @param message [String] full SMB2 message binary (header + body)
    # @return [String] 16-byte binary signature
    def self.sign(signing_key, message)
      msg = message.b.dup
      # Zero out the signature field before computing HMAC
      msg[SIGNATURE_OFFSET, SIGNATURE_LENGTH] = "\x00" * SIGNATURE_LENGTH
      OpenSSL::HMAC.digest("SHA256", signing_key.b, msg)[0, SIGNATURE_LENGTH]
    end

    # Verify the signature in an SMB2 message.
    #
    # Returns true if the message's Signature field matches the computed
    # HMAC-SHA256 (constant-time comparison to resist timing attacks).
    #
    # @param signing_key [String] signing key (from derive_signing_key)
    # @param message [String] full SMB2 message binary (header + body) with signature embedded
    # @return [Boolean] true if valid, false if invalid or message is too short
    def self.verify(signing_key, message)
      return false if message.bytesize < SIGNATURE_OFFSET + SIGNATURE_LENGTH

      received_sig = message.b[SIGNATURE_OFFSET, SIGNATURE_LENGTH]
      expected_sig = sign(signing_key, message)
      OpenSSL.fixed_length_secure_compare(received_sig, expected_sig)
    rescue
      false
    end
  end
end
