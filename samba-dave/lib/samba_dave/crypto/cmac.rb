# frozen_string_literal: true

require "openssl"

module SambaDave
  module Crypto
    # AES-128-CMAC (RFC 4493), used for SMB 3.x message signing.
    #
    # Implemented in pure Ruby over OpenSSL's AES-128-ECB single-block cipher,
    # because OpenSSL 3.x (as built for Ruby here) exposes no CMAC/MAC API. The
    # spec verifies it against the RFC 4493 known-answer vectors.
    module CMAC
      BLOCK = 16
      RB    = 0x87  # RFC 4493 constant for the 128-bit block polynomial

      module_function

      # @param key [String] 16-byte AES key
      # @param message [String] binary message
      # @return [String] 16-byte binary CMAC
      def digest(key, message)
        key = key.b
        message = message.b
        k1, k2 = subkeys(key)

        if message.empty?
          last = xor(pad(message), k2)
          blocks = []
        elsif (message.bytesize % BLOCK).zero?
          last = xor(message[-BLOCK, BLOCK], k1)
          blocks = slice_blocks(message[0...-BLOCK])
        else
          whole = (message.bytesize / BLOCK) * BLOCK
          last = xor(pad(message[whole..]), k2)
          blocks = slice_blocks(message[0...whole])
        end

        x = "\x00".b * BLOCK
        blocks.each { |block| x = aes_block(key, xor(x, block)) }
        aes_block(key, xor(x, last))
      end

      # Encrypt a single 16-byte block with AES-128 (no padding).
      def aes_block(key, block)
        cipher = OpenSSL::Cipher.new("aes-128-ecb")
        cipher.encrypt
        cipher.key = key
        cipher.padding = 0
        cipher.update(block) + cipher.final
      end

      # Derive the two CMAC subkeys K1, K2 from the block cipher.
      def subkeys(key)
        l = aes_block(key, "\x00".b * BLOCK)
        k1 = shift_and_reduce(l)
        k2 = shift_and_reduce(k1)
        [k1, k2]
      end

      # Left-shift a 16-byte string by one bit, XORing in RB when the high bit
      # was set (multiplication by x in GF(2^128)).
      def shift_and_reduce(input)
        bytes = input.bytes
        overflow = bytes[0] & 0x80
        shifted = []
        carry = 0
        bytes.reverse_each do |byte|
          value = (byte << 1) | carry
          carry = (value >> 8) & 1
          shifted.unshift(value & 0xff)
        end
        shifted[15] ^= RB unless overflow.zero?
        shifted.pack("C*")
      end

      # Pad a final partial block: append 0x80 then zeroes to 16 bytes.
      def pad(partial)
        (partial + "\x80".b).ljust(BLOCK, "\x00".b)
      end

      def slice_blocks(data)
        (data.bytesize / BLOCK).times.map { |i| data[i * BLOCK, BLOCK] }
      end

      def xor(a, b)
        a.bytes.zip(b.bytes).map { |x, y| x ^ y }.pack("C*")
      end

      private_class_method :aes_block, :subkeys, :shift_and_reduce, :pad, :slice_blocks, :xor
    end
  end
end
