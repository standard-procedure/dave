# frozen_string_literal: true

require "spec_helper"
require "samba_dave/protocol/transport"

RSpec.describe SambaDave::Protocol::Transport do
  let(:payload) { "Hello, SMB2!" }

  describe ".frame" do
    it "prepends a 4-byte NetBIOS session header" do
      framed = described_class.frame(payload)
      expect(framed.bytesize).to eq(4 + payload.bytesize)
    end

    it "sets the first byte to 0x00 (session message type)" do
      framed = described_class.frame(payload)
      expect(framed[0].ord).to eq(0x00)
    end

    it "encodes length as big-endian 3 bytes at positions 1-3" do
      data = "A" * 300  # 300 = 0x00012C
      framed = described_class.frame(data)
      expect(framed[1].ord).to eq(0x00)
      expect(framed[2].ord).to eq(0x01)
      expect(framed[3].ord).to eq(0x2C)
    end

    it "returns binary-safe string" do
      framed = described_class.frame("\x00\x01\x02")
      expect(framed.encoding).to eq(Encoding::BINARY)
    end

    it "frames an empty payload" do
      framed = described_class.frame("")
      expect(framed.bytesize).to eq(4)
      expect(framed[1..3]).to eq("\x00\x00\x00")
    end
  end

  describe ".read_message" do
    it "reads exactly the number of bytes specified in the frame header" do
      framed = described_class.frame(payload)
      io = StringIO.new(framed)
      result = described_class.read_message(io)
      expect(result).to eq(payload.b)
    end

    it "reads multiple sequential messages from the same stream" do
      message1 = "First message"
      message2 = "Second message"
      stream = StringIO.new(described_class.frame(message1) + described_class.frame(message2))

      result1 = described_class.read_message(stream)
      result2 = described_class.read_message(stream)

      expect(result1).to eq(message1.b)
      expect(result2).to eq(message2.b)
    end

    it "returns binary string" do
      framed = described_class.frame(payload)
      io = StringIO.new(framed)
      result = described_class.read_message(io)
      expect(result.encoding).to eq(Encoding::BINARY)
    end

    it "raises EOFError when stream is closed" do
      io = StringIO.new("")
      expect { described_class.read_message(io) }.to raise_error(EOFError)
    end

    it "handles large payloads (64KB)" do
      large_payload = "X" * 65_536
      framed = described_class.frame(large_payload)
      io = StringIO.new(framed)
      result = described_class.read_message(io)
      expect(result.bytesize).to eq(65_536)
    end
  end

  describe ".write_message" do
    it "writes a framed message to the IO object" do
      output = StringIO.new("".b)
      described_class.write_message(output, payload)
      output.rewind
      result = described_class.read_message(output)
      expect(result).to eq(payload.b)
    end

    it "writes multiple messages sequentially" do
      output = StringIO.new("".b)
      described_class.write_message(output, "msg1")
      described_class.write_message(output, "msg2")
      output.rewind
      expect(described_class.read_message(output)).to eq("msg1".b)
      expect(described_class.read_message(output)).to eq("msg2".b)
    end
  end
end
