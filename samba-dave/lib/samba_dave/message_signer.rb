# frozen_string_literal: true

require "openssl"
require "samba_dave/crypto/cmac"

module SambaDave
  # SMB2/3 message signing and verification.
  #
  # ## Signing algorithm (per dialect)
  #
  # The MAC depends on the negotiated dialect: SMB 2.0.2/2.1 use HMAC-SHA256,
  # SMB 3.x use AES-128-CMAC. #sign / #verify take an `algorithm:` selecting
  # between them (:hmac_sha256 default, :aes_cmac for SMB 3.x). The signature is
  # always the first 16 bytes.
  #
  # ## Signing Key
  #
  # For SMB 2.0.2/2.1, Session.SigningKey is the 16-byte session key itself (no
  # KDF). For SMB 3.x it is derived from the session key via the SP800-108 KDF
  # (see Session#set_session_key / Crypto::KDF). Either way the resulting key is
  # passed straight to #sign / #verify.
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
    # Offset of the Signature field in the SMB2 header (bytes 48-63)
    SIGNATURE_OFFSET = 48
    SIGNATURE_LENGTH = 16

    # Compute the 16-byte HMAC-SHA256 signature for an SMB2 message.
    #
    # The signature field in the message is zeroed before computing the HMAC.
    # The result is the first 16 bytes of the HMAC-SHA256 output.
    #
    # @param signing_key [String] the session's 16-byte SigningKey (see Session#set_session_key)
    # @param message [String] full SMB2 message binary (header + body)
    # @param algorithm [Symbol] :hmac_sha256 (SMB 2.x) or :aes_cmac (SMB 3.x)
    # @return [String] 16-byte binary signature
    def self.sign(signing_key, message, algorithm: :hmac_sha256)
      msg = message.b.dup
      # Zero out the signature field before computing the MAC
      msg[SIGNATURE_OFFSET, SIGNATURE_LENGTH] = "\x00" * SIGNATURE_LENGTH
      mac(algorithm, signing_key.b, msg)[0, SIGNATURE_LENGTH]
    end

    # Compute the raw MAC for the negotiated dialect's signing algorithm.
    def self.mac(algorithm, key, message)
      case algorithm
      when :hmac_sha256 then OpenSSL::HMAC.digest("SHA256", key, message)
      when :aes_cmac then Crypto::CMAC.digest(key, message)
      else raise ArgumentError, "unknown signing algorithm: #{algorithm.inspect}"
      end
    end

    # Verify the signature in an SMB2 message.
    #
    # Returns true if the message's Signature field matches the computed
    # HMAC-SHA256 (constant-time comparison to resist timing attacks).
    #
    # @param signing_key [String] the session's 16-byte SigningKey (see Session#set_session_key)
    # @param message [String] full SMB2 message binary (header + body) with signature embedded
    # @param algorithm [Symbol] :hmac_sha256 (SMB 2.x) or :aes_cmac (SMB 3.x)
    # @return [Boolean] true if valid, false if invalid or message is too short
    def self.verify(signing_key, message, algorithm: :hmac_sha256)
      return false if message.bytesize < SIGNATURE_OFFSET + SIGNATURE_LENGTH

      received_sig = message.b[SIGNATURE_OFFSET, SIGNATURE_LENGTH]
      expected_sig = sign(signing_key, message, algorithm: algorithm)
      OpenSSL.fixed_length_secure_compare(received_sig, expected_sig)
    rescue
      false
    end
  end
end
