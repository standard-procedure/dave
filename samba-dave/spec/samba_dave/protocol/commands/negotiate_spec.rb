# frozen_string_literal: true

require "spec_helper"
require "samba_dave/protocol/commands/negotiate"
require "samba_dave/protocol/constants"

RSpec.describe SambaDave::Protocol::Commands::Negotiate do
  let(:server_guid) { "A" * 16 }

  # ── Request parsing ──────────────────────────────────────────────────────────

  describe "NegotiateRequest" do
    subject(:request_class) { SambaDave::Protocol::Commands::NegotiateRequest }

    it "parses structure_size as 36" do
      raw = build_negotiate_request_binary(dialects: [0x0202, 0x0210])
      req = request_class.read(raw)
      expect(req.structure_size).to eq(36)
    end

    it "parses dialect_count" do
      raw = build_negotiate_request_binary(dialects: [0x0202, 0x0210])
      req = request_class.read(raw)
      expect(req.dialect_count).to eq(2)
    end

    it "parses dialect list" do
      raw = build_negotiate_request_binary(dialects: [0x0202, 0x0210, 0x0300])
      req = request_class.read(raw)
      expect(req.dialects.to_a).to eq([0x0202, 0x0210, 0x0300])
    end

    it "parses client_guid as 16 bytes" do
      raw = build_negotiate_request_binary(dialects: [0x0202])
      req = request_class.read(raw)
      expect(req.client_guid.bytesize).to eq(16)
    end

    it "parses security_mode" do
      raw = build_negotiate_request_binary(dialects: [0x0202], security_mode: 0x0001)
      req = request_class.read(raw)
      expect(req.security_mode).to eq(0x0001)
    end
  end

  # ── Response building ─────────────────────────────────────────────────────────

  describe "NegotiateResponse" do
    subject(:response_class) { SambaDave::Protocol::Commands::NegotiateResponse }

    it "has structure_size of 65" do
      resp = response_class.new
      expect(resp.structure_size).to eq(65)
    end

    it "can set dialect_revision" do
      resp = response_class.new(dialect_revision: 0x0202)
      expect(resp.dialect_revision).to eq(0x0202)
    end

    it "can store server_guid" do
      resp = response_class.new(server_guid: server_guid)
      expect(resp.server_guid).to eq(server_guid)
    end

    it "can store a security buffer" do
      token = "spnego_token_bytes"
      resp = response_class.new(security_buffer: token)
      expect(resp.security_buffer).to eq(token)
    end
  end

  # ── Command handler ───────────────────────────────────────────────────────────

  describe ".handle" do
    let(:handler) { described_class }

    it "responds to a NEGOTIATE request offering SMB 2.0.2" do
      raw = build_negotiate_request_binary(dialects: [0x0202])
      request = SambaDave::Protocol::Commands::NegotiateRequest.read(raw)
      response_body = handler.handle(request, server_guid: server_guid)
      resp = SambaDave::Protocol::Commands::NegotiateResponse.read(response_body)

      expect(resp.dialect_revision).to eq(0x0202)
    end

    it "selects SMB 2.1 (0x0210) when multiple dialects including 0x0210 are offered" do
      raw = build_negotiate_request_binary(dialects: [0x0202, 0x0210, 0x0302, 0x0311])
      request = SambaDave::Protocol::Commands::NegotiateRequest.read(raw)
      response_body = handler.handle(request, server_guid: server_guid)
      resp = SambaDave::Protocol::Commands::NegotiateResponse.read(response_body)

      expect(resp.dialect_revision).to eq(0x0210)
    end

    it "includes server GUID in the response" do
      raw = build_negotiate_request_binary(dialects: [0x0202])
      request = SambaDave::Protocol::Commands::NegotiateRequest.read(raw)
      response_body = handler.handle(request, server_guid: server_guid)
      resp = SambaDave::Protocol::Commands::NegotiateResponse.read(response_body)

      expect(resp.server_guid).to eq(server_guid)
    end

    it "includes a non-empty security buffer (SPNEGO token)" do
      raw = build_negotiate_request_binary(dialects: [0x0202])
      request = SambaDave::Protocol::Commands::NegotiateRequest.read(raw)
      response_body = handler.handle(request, server_guid: server_guid)
      resp = SambaDave::Protocol::Commands::NegotiateResponse.read(response_body)

      expect(resp.security_buffer_length).to be > 0
      expect(resp.security_buffer.bytesize).to eq(resp.security_buffer_length)
    end

    it "sets SecurityBufferOffset pointing 128 bytes from the message start" do
      raw = build_negotiate_request_binary(dialects: [0x0202])
      request = SambaDave::Protocol::Commands::NegotiateRequest.read(raw)
      response_body = handler.handle(request, server_guid: server_guid)
      resp = SambaDave::Protocol::Commands::NegotiateResponse.read(response_body)

      # SecurityBufferOffset = 64 (header) + 64 (fixed body) = 128
      expect(resp.security_buffer_offset).to eq(128)
    end

    it "sets security mode to SIGNING_ENABLED" do
      raw = build_negotiate_request_binary(dialects: [0x0202])
      request = SambaDave::Protocol::Commands::NegotiateRequest.read(raw)
      response_body = handler.handle(request, server_guid: server_guid)
      resp = SambaDave::Protocol::Commands::NegotiateResponse.read(response_body)

      expect(resp.security_mode & 0x0001).to eq(0x0001)
    end

    it "sets MaxTransactSize, MaxReadSize, MaxWriteSize to 8MB" do
      raw = build_negotiate_request_binary(dialects: [0x0202])
      request = SambaDave::Protocol::Commands::NegotiateRequest.read(raw)
      response_body = handler.handle(request, server_guid: server_guid)
      resp = SambaDave::Protocol::Commands::NegotiateResponse.read(response_body)

      expect(resp.max_transact_size).to eq(8_388_608)
      expect(resp.max_read_size).to eq(8_388_608)
      expect(resp.max_write_size).to eq(8_388_608)
    end

    it "sets a non-zero system_time" do
      raw = build_negotiate_request_binary(dialects: [0x0202])
      request = SambaDave::Protocol::Commands::NegotiateRequest.read(raw)
      response_body = handler.handle(request, server_guid: server_guid)
      resp = SambaDave::Protocol::Commands::NegotiateResponse.read(response_body)

      expect(resp.system_time).to be > 0
    end
  end

  # ── SPNEGO token ─────────────────────────────────────────────────────────────

  describe SambaDave::Protocol::Commands::Negotiate::SPNEGO do
    describe ".neg_token_init" do
      it "returns binary data" do
        token = described_class.neg_token_init
        expect(token.encoding).to eq(Encoding::BINARY)
      end

      it "starts with APPLICATION [0] ASN.1 tag (0x60)" do
        token = described_class.neg_token_init
        expect(token[0].ord).to eq(0x60)
      end

      it "contains the NTLMSSP OID bytes" do
        token = described_class.neg_token_init
        # NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
        ntlmssp_oid = "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a".b
        expect(token).to include(ntlmssp_oid)
      end

      it "is at least 20 bytes long" do
        token = described_class.neg_token_init
        expect(token.bytesize).to be >= 20
      end
    end
  end

  # ── Helpers ────────────────────────────────────────────────────────────────

  def build_negotiate_request_binary(dialects:, security_mode: 0x0000)
    dialect_count = dialects.size
    [
      36, dialect_count, security_mode, 0,  # structure_size, dialect_count, security_mode, reserved
      0,                                     # capabilities
      "\x00" * 16,                           # client_guid
      0                                      # client_start_time
    ].then do |fields|
      [
        fields[0], fields[1], fields[2], fields[3]
      ].pack("S<S<S<S<") +
        [fields[4]].pack("L<") +
        fields[5] +
        [fields[6]].pack("Q<") +
        dialects.pack("S<*")
    end
  end
end
