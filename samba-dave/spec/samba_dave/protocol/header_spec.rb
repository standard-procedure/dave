# frozen_string_literal: true

require "spec_helper"
require "samba_dave/protocol/header"

RSpec.describe SambaDave::Protocol::Header do
  let(:minimal_header) do
    described_class.new(
      command: 0x0000,
      message_id: 1
    )
  end

  describe "structure" do
    it "is exactly 64 bytes when serialised" do
      expect(minimal_header.to_binary_s.bytesize).to eq(64)
    end

    it "starts with the SMB2 protocol ID (0xFE 'SMB')" do
      binary = minimal_header.to_binary_s
      expect(binary[0, 4]).to eq("\xFESMB".b)
    end

    it "has StructureSize of 64" do
      expect(minimal_header.structure_size).to eq(64)
    end

    it "has zero signature by default (16 zero bytes)" do
      expect(minimal_header.signature).to eq("\x00" * 16)
    end
  end

  describe "field access" do
    it "stores the command code" do
      header = described_class.new(command: 0x0005)
      expect(header.command).to eq(0x0005)
    end

    it "stores the message_id" do
      header = described_class.new(message_id: 42)
      expect(header.message_id).to eq(42)
    end

    it "stores status code" do
      header = described_class.new(status: 0x00000000)
      expect(header.status).to eq(0)
    end

    it "stores session_id" do
      header = described_class.new(session_id: 0x0000000000001234)
      expect(header.session_id).to eq(0x1234)
    end

    it "stores tree_id" do
      header = described_class.new(tree_id: 0xDEAD)
      expect(header.tree_id).to eq(0xDEAD)
    end

    it "stores flags" do
      header = described_class.new(flags: 0x00000001)
      expect(header.flags).to eq(0x00000001)
    end

    it "stores credit_charge" do
      header = described_class.new(credit_charge: 1)
      expect(header.credit_charge).to eq(1)
    end

    it "stores credit_request (renamed from credit_req_resp)" do
      header = described_class.new(credit_request: 31)
      expect(header.credit_request).to eq(31)
    end
  end

  describe "response header" do
    it "can set the SERVER_TO_REDIR flag" do
      header = described_class.new(flags: 0x00000001)
      expect(header.flags & 0x00000001).to eq(1)
    end
  end

  describe "serialisation / deserialisation" do
    it "round-trips correctly through binary" do
      original = described_class.new(
        command: 0x0000,
        message_id: 7,
        status: 0x00000000,
        flags: 0x00000001,
        tree_id: 0xABCD,
        session_id: 0x0000000000001234
      )
      binary = original.to_binary_s
      restored = described_class.read(binary)

      expect(restored.command).to eq(0x0000)
      expect(restored.message_id).to eq(7)
      expect(restored.status).to eq(0)
      expect(restored.flags).to eq(0x00000001)
      expect(restored.tree_id).to eq(0xABCD)
      expect(restored.session_id).to eq(0x1234)
    end

    it "serialises as little-endian" do
      # Command 0x0001 at offset 12 should appear as bytes 01 00 in the binary
      header = described_class.new(command: 0x0001)
      binary = header.to_binary_s
      # command is at byte offset 12
      expect(binary[12].ord).to eq(0x01)
      expect(binary[13].ord).to eq(0x00)
    end

    it "parses a raw SMB2 header binary correctly" do
      # Build a known binary header
      raw = [
        "\xFE", "S", "M", "B",    # protocol_id (4)
        "\x40\x00",                # structure_size = 64 (2)
        "\x00\x00",                # credit_charge (2)
        "\x00\x00\x00\x00",       # status (4)
        "\x00\x00",                # command = NEGOTIATE (2)
        "\x01\x00",                # credit_request = 1 (2)
        "\x00\x00\x00\x00",       # flags (4)
        "\x00\x00\x00\x00",       # next_command (4)
        "\x01\x00\x00\x00\x00\x00\x00\x00",  # message_id = 1 (8)
        "\x00\x00\x00\x00",       # reserved (4)
        "\x00\x00\x00\x00",       # tree_id (4)
        "\x00\x00\x00\x00\x00\x00\x00\x00",  # session_id (8)
        "\x00" * 16               # signature (16)
      ].join.b

      expect(raw.bytesize).to eq(64)

      header = described_class.read(raw)
      expect(header.command).to eq(0x0000)
      expect(header.message_id).to eq(1)
      expect(header.structure_size).to eq(64)
    end
  end

  describe ".response_for" do
    it "creates a response header from a request header" do
      request = described_class.new(
        command: 0x0000,
        message_id: 5,
        session_id: 0x1234
      )
      response = described_class.response_for(request, status: 0)

      expect(response.command).to eq(0x0000)
      expect(response.message_id).to eq(5)
      expect(response.session_id).to eq(0x1234)
      expect(response.flags & SambaDave::Protocol::Constants::Flags::SERVER_TO_REDIR).to eq(
        SambaDave::Protocol::Constants::Flags::SERVER_TO_REDIR
      )
      expect(response.status).to eq(0)
    end
  end
end
