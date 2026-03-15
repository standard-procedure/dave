# frozen_string_literal: true

require "spec_helper"
require "net/ntlm"
require "samba_dave/ntlm/spnego"
require "samba_dave/ntlm/challenge"
require "samba_dave/security_provider"
require "samba_dave/authenticator"
require "samba_dave/session"
require "samba_dave/protocol/commands/session_setup"

RSpec.describe SambaDave::Protocol::Commands::SessionSetup do
  let(:username) { "testuser" }
  let(:password) { "testpass" }
  let(:provider)      { SambaDave::TestSecurityProvider.new(username => password) }
  let(:authenticator) { SambaDave::Authenticator.new(provider) }
  let(:sessions)      { {} }  # session_id => Session
  let(:session_id)    { 0x0000000000000001 }

  # Helpers for building request bodies

  def build_session_setup_request(security_buffer)
    # SESSION_SETUP Request fixed body (24 bytes):
    #   StructureSize (2) + Flags (1) + SecurityMode (1) + Capabilities (4) +
    #   Channel (4) + SecurityBufferOffset (2) + SecurityBufferLength (2) +
    #   PreviousSessionId (8) = 24 bytes
    [
      25,                                  # structure_size (uint16)
      0,                                   # flags (uint8)
      1,                                   # security_mode (uint8)
      0,                                   # capabilities (uint32)
      0,                                   # channel (uint32)
      security_buffer_offset,              # security_buffer_offset (uint16)
      security_buffer.bytesize,            # security_buffer_length (uint16)
      0                                    # previous_session_id (uint64)
    ].pack("S<CCL<L<S<S<Q<") + security_buffer
  end

  def security_buffer_offset
    # offset from start of SMB2 message = header(64) + body_fixed(24)
    64 + 24
  end

  def build_type1_spnego
    type1_bytes = Net::NTLM::Message::Type1.new.serialize.b
    build_spnego_neg_token_init(type1_bytes)
  end

  def build_type3_spnego(type2_bytes)
    t2 = Net::NTLM::Message.parse(type2_bytes)
    t3 = t2.response(
      { user: username, password: password, domain: "" },
      { ntlmv2: true }
    )
    build_spnego_neg_token_resp(t3.serialize.b)
  end

  # ── BinData structures ───────────────────────────────────────────────────────

  describe "SessionSetupRequest" do
    subject(:klass) { SambaDave::Protocol::Commands::SessionSetupRequest }

    it "parses structure_size as 25" do
      raw = build_session_setup_request(build_type1_spnego)
      req = klass.read(raw)
      expect(req.structure_size).to eq(25)
    end

    it "parses security_buffer_length" do
      spnego = build_type1_spnego
      raw = build_session_setup_request(spnego)
      req = klass.read(raw)
      expect(req.security_buffer_length).to eq(spnego.bytesize)
    end
  end

  describe "SessionSetupResponse" do
    subject(:klass) { SambaDave::Protocol::Commands::SessionSetupResponse }

    it "has structure_size of 9" do
      resp = klass.new
      expect(resp.structure_size).to eq(9)
    end

    it "can store a security buffer" do
      resp = klass.new(security_buffer: "test_token".b)
      expect(resp.security_buffer).to eq("test_token".b)
    end
  end

  # ── Round 1: NEGOTIATE_MESSAGE (Type 1) → CHALLENGE (Type 2) ────────────────

  describe ".handle — Round 1" do
    let(:spnego1) { build_type1_spnego }
    let(:request_body) { build_session_setup_request(spnego1) }

    subject(:result) do
      described_class.handle(
        request_body,
        session_id: session_id,
        authenticator: authenticator,
        sessions: sessions
      )
    end

    it "returns a hash with :status and :body" do
      expect(result).to have_key(:status)
      expect(result).to have_key(:body)
    end

    it "returns STATUS_MORE_PROCESSING_REQUIRED" do
      expect(result[:status]).to eq(SambaDave::Protocol::Constants::Status::MORE_PROCESSING_REQUIRED)
    end

    it "includes a non-empty security buffer in the response body" do
      response = SambaDave::Protocol::Commands::SessionSetupResponse.read(result[:body])
      expect(response.security_buffer_length).to be > 0
      expect(response.security_buffer.bytesize).to eq(response.security_buffer_length)
    end

    it "security buffer contains a Type2 (CHALLENGE) message" do
      response = SambaDave::Protocol::Commands::SessionSetupResponse.read(result[:body])
      ntlm_bytes = SambaDave::NTLM::SPNEGO.unwrap(response.security_buffer)
      expect(ntlm_bytes[8, 4]).to eq("\x02\x00\x00\x00".b)  # type = 2
    end

    it "does NOT create an authenticated session yet" do
      described_class.handle(
        request_body,
        session_id: session_id,
        authenticator: authenticator,
        sessions: sessions
      )
      expect(sessions[session_id]&.authenticated?).to be_falsey
    end
  end

  # ── Round 2: AUTHENTICATE (Type 3) → SUCCESS ────────────────────────────────

  describe ".handle — Round 2 (correct credentials)" do
    def do_round2
      # Round 1
      spnego1 = build_type1_spnego
      round1_result = described_class.handle(
        build_session_setup_request(spnego1),
        session_id: session_id,
        authenticator: authenticator,
        sessions: sessions
      )

      # Extract Type2 from Round 1 response
      round1_response = SambaDave::Protocol::Commands::SessionSetupResponse.read(round1_result[:body])
      type2_bytes = SambaDave::NTLM::SPNEGO.unwrap(round1_response.security_buffer)

      # Build Type3 with correct password
      spnego3 = build_type3_spnego(type2_bytes)

      # Round 2
      described_class.handle(
        build_session_setup_request(spnego3),
        session_id: session_id,
        authenticator: authenticator,
        sessions: sessions
      )
    end

    it "returns STATUS_SUCCESS" do
      result = do_round2
      expect(result[:status]).to eq(SambaDave::Protocol::Constants::Status::SUCCESS)
    end

    it "creates an authenticated session" do
      do_round2
      expect(sessions[session_id]).not_to be_nil
      expect(sessions[session_id].authenticated?).to be true
    end

    it "stores the user identity in the session" do
      do_round2
      expect(sessions[session_id].user_identity).not_to be_nil
      expect(sessions[session_id].user_identity[:username]).to eq(username)
    end
  end

  describe ".handle — Round 2 (wrong credentials)" do
    def do_round2_wrong_password
      spnego1 = build_type1_spnego
      round1_result = described_class.handle(
        build_session_setup_request(spnego1),
        session_id: session_id,
        authenticator: authenticator,
        sessions: sessions
      )

      round1_response = SambaDave::Protocol::Commands::SessionSetupResponse.read(round1_result[:body])
      type2_bytes = SambaDave::NTLM::SPNEGO.unwrap(round1_response.security_buffer)

      # Build Type3 with WRONG password
      t2 = Net::NTLM::Message.parse(type2_bytes)
      t3 = t2.response(
        { user: username, password: "wrongpassword", domain: "" },
        { ntlmv2: true }
      )
      spnego3 = build_spnego_neg_token_resp(t3.serialize.b)

      described_class.handle(
        build_session_setup_request(spnego3),
        session_id: session_id,
        authenticator: authenticator,
        sessions: sessions
      )
    end

    it "returns STATUS_LOGON_FAILURE" do
      result = do_round2_wrong_password
      expect(result[:status]).to eq(SambaDave::Protocol::Constants::Status::LOGON_FAILURE)
    end

    it "does NOT create an authenticated session" do
      do_round2_wrong_password
      expect(sessions[session_id]&.authenticated?).to be_falsey
    end
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  def der_length(len)
    if len < 128
      [len].pack("C")
    elsif len < 256
      "\x81".b + [len].pack("C")
    else
      "\x82".b + [len].pack("n")
    end
  end

  def der_tlv(tag, value)
    ([tag].pack("C") + der_length(value.bytesize) + value).b
  end

  def build_spnego_neg_token_init(ntlm_payload)
    ntlmssp_oid = "\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a".b
    spnego_oid  = "\x06\x06\x2b\x06\x01\x05\x05\x02".b

    mech_types     = der_tlv(0x30, ntlmssp_oid)
    mech_types_ctx = der_tlv(0xa0, mech_types)
    octet_string   = der_tlv(0x04, ntlm_payload)
    mech_token_ctx = der_tlv(0xa2, octet_string)
    neg_init_seq   = der_tlv(0x30, mech_types_ctx + mech_token_ctx)
    neg_init_ctx   = der_tlv(0xa0, neg_init_seq)
    der_tlv(0x60, spnego_oid + neg_init_ctx)
  end

  def build_spnego_neg_token_resp(ntlm_payload)
    octet_string       = der_tlv(0x04, ntlm_payload)
    response_token_ctx = der_tlv(0xa2, octet_string)
    sequence           = der_tlv(0x30, response_token_ctx)
    der_tlv(0xa1, sequence)
  end
end
