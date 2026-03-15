# frozen_string_literal: true

require "spec_helper"
require "net/ntlm"
require "samba_dave/ntlm/spnego"
require "samba_dave/ntlm/challenge"
require "samba_dave/security_provider"
require "samba_dave/authenticator"

RSpec.describe SambaDave::Authenticator do
  let(:username) { "alice" }
  let(:password) { "s3cr3tP@ss" }

  let(:provider) do
    SambaDave::TestSecurityProvider.new(username => password)
  end

  subject(:authenticator) { described_class.new(provider) }

  # ── begin_auth (Round 1) ─────────────────────────────────────────────────────

  describe "#begin_auth" do
    let(:session_id) { 42 }
    let(:type1_bytes) { Net::NTLM::Message::Type1.new.serialize.b }
    let(:type1_spnego) { build_spnego_neg_token_init(type1_bytes) }

    it "returns a non-empty binary security buffer" do
      result = authenticator.begin_auth(session_id, type1_spnego)
      expect(result).to be_a(String)
      expect(result.encoding).to eq(Encoding::BINARY)
      expect(result.bytesize).to be > 10
    end

    it "returns a NegTokenResp (0xa1 tag) wrapping a Type2 challenge" do
      result = authenticator.begin_auth(session_id, type1_spnego)
      # NegTokenResp starts with [1] context tag
      expect(result[0].ord).to eq(0xa1)
    end

    it "contains the NTLM Type2 signature inside the response" do
      result = authenticator.begin_auth(session_id, type1_spnego)
      # SPNEGO-unwrap should give us the Type2 bytes
      ntlm_bytes = SambaDave::NTLM::SPNEGO.unwrap(result)
      expect(ntlm_bytes[0, 8]).to eq("NTLMSSP\x00".b)
      expect(ntlm_bytes[8, 4]).to eq("\x02\x00\x00\x00".b)  # type = 2
    end

    it "stores a pending challenge for the session" do
      authenticator.begin_auth(session_id, type1_spnego)
      # The challenge should be stored — verify by completing auth
      expect(authenticator.pending_challenge?(session_id)).to be true
    end

    it "handles raw NTLM Type1 (no SPNEGO wrapper)" do
      result = authenticator.begin_auth(session_id, type1_bytes)
      expect(result[0].ord).to eq(0xa1)
    end
  end

  # ── complete_auth (Round 2) ──────────────────────────────────────────────────

  describe "#complete_auth" do
    let(:session_id) { 99 }

    def perform_round1_and_build_type3(provider_password = password)
      # Perform Round 1
      type1_bytes = Net::NTLM::Message::Type1.new.serialize.b
      spnego1 = build_spnego_neg_token_init(type1_bytes)
      round1_response = authenticator.begin_auth(session_id, spnego1)

      # Extract Type2 from Round 1 response
      type2_bytes = SambaDave::NTLM::SPNEGO.unwrap(round1_response)
      type2 = Net::NTLM::Message.parse(type2_bytes)

      # Build a Type3 response using the correct password
      type3 = type2.response(
        { user: username, password: provider_password, domain: "" },
        { ntlmv2: true }
      )
      type3.serialize.b
    end

    context "with correct credentials" do
      it "returns an identity" do
        type3_bytes = perform_round1_and_build_type3
        spnego3 = build_spnego_neg_token_resp(type3_bytes)
        result = authenticator.complete_auth(session_id, spnego3)
        expect(result).not_to be_nil
      end

      it "includes the username in the returned identity" do
        type3_bytes = perform_round1_and_build_type3
        spnego3 = build_spnego_neg_token_resp(type3_bytes)
        result = authenticator.complete_auth(session_id, spnego3)
        expect(result[:username]).to eq(username)
      end

      it "clears the pending challenge after completion" do
        type3_bytes = perform_round1_and_build_type3
        spnego3 = build_spnego_neg_token_resp(type3_bytes)
        authenticator.complete_auth(session_id, spnego3)
        expect(authenticator.pending_challenge?(session_id)).to be false
      end
    end

    context "with incorrect password" do
      it "returns nil" do
        type3_bytes = perform_round1_and_build_type3("wrongpassword")
        spnego3 = build_spnego_neg_token_resp(type3_bytes)
        result = authenticator.complete_auth(session_id, spnego3)
        expect(result).to be_nil
      end
    end

    context "with unknown username" do
      it "returns nil when user not in provider" do
        type1_bytes = Net::NTLM::Message::Type1.new.serialize.b
        round1_response = authenticator.begin_auth(session_id, type1_bytes)
        type2_bytes = SambaDave::NTLM::SPNEGO.unwrap(round1_response)
        type2 = Net::NTLM::Message.parse(type2_bytes)

        type3 = type2.response(
          { user: "nobody", password: "whatever", domain: "" },
          { ntlmv2: true }
        )
        type3_bytes = type3.serialize.b
        spnego3 = build_spnego_neg_token_resp(type3_bytes)
        result = authenticator.complete_auth(session_id, spnego3)
        expect(result).to be_nil
      end
    end

    context "without a preceding begin_auth" do
      it "returns nil (no pending challenge)" do
        type3_bytes = "NTLMSSP\x00\x03garbage".b
        result = authenticator.complete_auth(session_id, type3_bytes)
        expect(result).to be_nil
      end
    end

    context "with raw NTLM (no SPNEGO wrapper)" do
      it "also works with unwrapped Type3 bytes" do
        type3_bytes = perform_round1_and_build_type3
        # Pass raw Type3 bytes directly (no SPNEGO wrapping)
        result = authenticator.complete_auth(session_id, type3_bytes)
        expect(result).not_to be_nil
      end
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
