# frozen_string_literal: true

require "openssl"

module SambaDave
  module Crypto
    # SP800-108 counter-mode key derivation, the "SMB3KDF" used to derive SMB 3.x
    # signing and encryption keys from the session key.
    module KDF
      module_function

      # SP800-108 §5.1 KDF in Counter Mode with HMAC-SHA256 as the PRF, as SMB3
      # parameterises it: r = 32 (a 32-bit counter), L = the output length in
      # bits. For all SMB3 keys L = 128, which is <= one HMAC-SHA256 block, so a
      # single iteration suffices.
      #
      # Fixed input = counter(4, BE) || Label || 0x00 || Context || L-in-bits(4, BE)
      #
      # SMB labels/contexts are passed WITH their own trailing NUL (as MS defines
      # them, e.g. "SMB2AESCMAC\0" / "SmbSign\0"); the 0x00 here is the separator
      # SP800-108 places between Label and Context.
      #
      # @param key [String] the key derivation key (the 16-byte SessionKey)
      # @param label [String] purpose label (binary, incl. its trailing NUL)
      # @param context [String] context (binary, incl. its trailing NUL)
      # @param length [Integer] output length in bytes (default 16)
      # @return [String] derived key
      def sp800_108_counter(key:, label:, context:, length: 16)
        bits = length * 8
        fixed = [1].pack("N") + label.b + "\x00".b + context.b + [bits].pack("N")
        OpenSSL::HMAC.digest("SHA256", key.b, fixed)[0, length]
      end
    end
  end
end
