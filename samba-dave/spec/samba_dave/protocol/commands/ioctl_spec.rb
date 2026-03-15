# frozen_string_literal: true

require "spec_helper"
require "samba_dave/open_file_table"
require "samba_dave/protocol/commands/ioctl"

RSpec.describe SambaDave::Protocol::Commands::Ioctl do
  C = SambaDave::Protocol::Constants

  FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204
  FSCTL_GET_REPARSE_POINT       = 0x000900A8
  FSCTL_SOME_UNKNOWN            = 0x00110001

  let(:server_guid) { "G" * 16 }

  # Build an IOCTL request body (56-byte fixed portion + input buffer).
  # MS-SMB2 section 2.2.31
  #   StructureSize (2) = 57
  #   Reserved (2)
  #   CtlCode (4)
  #   FileId.Persistent (8)
  #   FileId.Volatile (8)
  #   InputOffset (4) = 64+56 = 120 (offset from SMB2 header start)
  #   InputCount (4)
  #   MaxInputResponse (4)
  #   OutputOffset (4)
  #   OutputCount (4)
  #   MaxOutputResponse (4)
  #   Flags (4) = 1 (IS_FSCTL)
  #   Reserved2 (4)
  # Total fixed = 2+2+4+8+8+4+4+4+4+4+4+4+4 = 56 bytes
  def build_ioctl_body(ctl_code:, input_buf: "", file_id: "\x00" * 16)
    persistent = file_id[0, 8].unpack1("Q<")
    volatile   = file_id[8, 8].unpack1("Q<")
    input_offset  = 120  # 64-byte header + 56-byte fixed body
    input_count   = input_buf.bytesize
    output_offset = input_offset + input_count
    [
      57, 0, ctl_code,
      persistent, volatile,
      input_offset, input_count, 0,
      output_offset, 0, 4096,
      1, 0   # Flags=IS_FSCTL, Reserved2
    ].pack("S<S<L<Q<Q<L<L<L<L<L<L<L<L<") + input_buf.b
  end

  # Build FSCTL_VALIDATE_NEGOTIATE_INFO input buffer
  # Capabilities(4) + Guid(16) + SecurityMode(2) + DialectCount(2) + Dialects[](2 each)
  def build_validate_negotiate_input(dialects: [0x0202], guid: "C" * 16, capabilities: 0, security_mode: 1)
    dialect_count = dialects.size
    buf = [capabilities].pack("L<")
    buf += guid.b
    buf += [security_mode, dialect_count].pack("S<S<")
    dialects.each { |d| buf += [d].pack("S<") }
    buf
  end

  # ── FSCTL_VALIDATE_NEGOTIATE_INFO ─────────────────────────────────────────

  describe "FSCTL_VALIDATE_NEGOTIATE_INFO (0x00140204)" do
    it "returns STATUS_SUCCESS" do
      input = build_validate_negotiate_input
      body  = build_ioctl_body(ctl_code: FSCTL_VALIDATE_NEGOTIATE_INFO, input_buf: input)
      result = described_class.handle(body, server_guid: server_guid)
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "returns a non-empty response body" do
      input = build_validate_negotiate_input
      body  = build_ioctl_body(ctl_code: FSCTL_VALIDATE_NEGOTIATE_INFO, input_buf: input)
      result = described_class.handle(body, server_guid: server_guid)
      expect(result[:body]).not_to be_empty
    end

    it "includes server_guid in the response output buffer" do
      input = build_validate_negotiate_input
      body  = build_ioctl_body(ctl_code: FSCTL_VALIDATE_NEGOTIATE_INFO, input_buf: input)
      result = described_class.handle(body, server_guid: server_guid)

      # Parse the IOCTL response body to extract output buffer
      # IoctlResponse fixed = 2+2+4+8+8+4+4+4+4 = 40 bytes
      resp_body = result[:body]
      ioctl_resp = SambaDave::Protocol::Commands::IoctlResponse.read(resp_body)
      # ValidateNegotiateInfo response: Capabilities(4) + Guid(16) + SecurityMode(2) + Dialect(2)
      out_buf = ioctl_resp.output_buffer
      guid_in_response = out_buf[4, 16]
      expect(guid_in_response).to eq(server_guid.b)
    end

    it "includes dialect 0x0202 in the response output buffer" do
      input = build_validate_negotiate_input
      body  = build_ioctl_body(ctl_code: FSCTL_VALIDATE_NEGOTIATE_INFO, input_buf: input)
      result = described_class.handle(body, server_guid: server_guid)

      resp_body  = result[:body]
      ioctl_resp = SambaDave::Protocol::Commands::IoctlResponse.read(resp_body)
      out_buf    = ioctl_resp.output_buffer
      # ValidateNegotiateInfo response layout: Capabilities(4) Guid(16) SecurityMode(2) Dialect(2)
      dialect = out_buf[22, 2].unpack1("S<")
      expect(dialect).to eq(0x0202)
    end
  end

  # ── FSCTL_GET_REPARSE_POINT ───────────────────────────────────────────────

  describe "FSCTL_GET_REPARSE_POINT (0x000900A8)" do
    it "returns STATUS_NOT_A_REPARSE_POINT" do
      body   = build_ioctl_body(ctl_code: FSCTL_GET_REPARSE_POINT)
      result = described_class.handle(body, server_guid: server_guid)
      expect(result[:status]).to eq(C::Status::NOT_A_REPARSE_POINT)
    end

    it "returns an empty body" do
      body   = build_ioctl_body(ctl_code: FSCTL_GET_REPARSE_POINT)
      result = described_class.handle(body, server_guid: server_guid)
      expect(result[:body]).to eq("")
    end
  end

  # ── Unknown IOCTL codes ───────────────────────────────────────────────────

  describe "unknown IOCTL code" do
    it "returns STATUS_NOT_SUPPORTED" do
      body   = build_ioctl_body(ctl_code: FSCTL_SOME_UNKNOWN)
      result = described_class.handle(body, server_guid: server_guid)
      expect(result[:status]).to eq(C::Status::NOT_SUPPORTED)
    end

    it "returns an empty body for unknown codes" do
      body   = build_ioctl_body(ctl_code: FSCTL_SOME_UNKNOWN)
      result = described_class.handle(body, server_guid: server_guid)
      expect(result[:body]).to eq("")
    end
  end
end
