# frozen_string_literal: true

module SambaDave
  module Protocol
    # NetBIOS Session Service transport framing for SMB2 over TCP.
    #
    # Every SMB2 message on the wire is prefixed with a 4-byte frame header:
    #   Byte 0:   0x00 (session message type — always zero)
    #   Bytes 1-3: message length, big-endian 3-byte unsigned integer
    #
    # This module provides three class methods:
    #   - Transport.frame(data)           — prepend length header, return binary string
    #   - Transport.read_message(io)      — read one framed message from an IO-like object
    #   - Transport.write_message(io, data) — frame and write one message to an IO object
    #
    module Transport
      # @param data [String] raw SMB2 message bytes
      # @return [String] 4-byte NetBIOS frame header + data (binary-safe)
      def self.frame(data)
        data = data.b if data.encoding != Encoding::BINARY
        length = data.bytesize
        header = [
          0x00,                 # session message type
          (length >> 16) & 0xFF,
          (length >> 8) & 0xFF,
          length & 0xFF
        ].pack("C4".freeze)
        (header + data).b
      end

      # Read exactly one framed SMB2 message from the given IO-like object.
      #
      # @param io [IO, StringIO] socket or stream to read from
      # @return [String] the raw SMB2 message bytes (without the 4-byte frame header)
      # @raise [EOFError] if the stream is at EOF or returns nil/empty
      def self.read_message(io)
        header = io.read(4)
        raise EOFError, "connection closed" if header.nil? || header.bytesize < 4

        # First byte is the session message type (always 0x00 — ignore it)
        length = ((header[1].ord << 16) | (header[2].ord << 8) | header[3].ord)

        return "".b if length.zero?

        data = io.read(length)
        raise EOFError, "truncated message (expected #{length} bytes)" if data.nil? || data.bytesize < length

        data.b
      end

      # Frame and write one SMB2 message to the given IO-like object.
      #
      # @param io [IO, StringIO] socket or stream to write to
      # @param data [String] raw SMB2 message bytes
      def self.write_message(io, data)
        io.write(frame(data))
      end
    end
  end
end
