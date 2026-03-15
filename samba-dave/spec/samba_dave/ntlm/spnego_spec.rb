# frozen_string_literal: true

require "spec_helper"
require "net/ntlm"
require "samba_dave/ntlm/spnego"

RSpec.describe SambaDave::NTLM::SPNEGO do
  # ── .unwrap ─────────────────────────────────────────────────────────────────

  describe ".unwrap" do
    context "when given a raw NTLM token (no SPNEGO wrapping)" do
      let(:raw_ntlm) { "NTLMSSP\x00\x01\x00\x00\x00\xFF\xFF\xFF\xFF".b }

      it "returns the token as-is" do
        result = described_class.unwrap(raw_ntlm)
        expect(result).to eq(raw_ntlm)
      end
    end

    context "when given a SPNEGO NegTokenInit (0x60 Application tag) with mechToken" do
      let(:ntlm_payload) { build_type1_bytes }
      let(:token) { build_neg_token_init_with_mech_token(ntlm_payload) }

      it "extracts the NTLM payload from the mechToken" do
        result = described_class.unwrap(token)
        expect(result).to eq(ntlm_payload)
      end

      it "returns binary encoding" do
        result = described_class.unwrap(token)
        expect(result.encoding).to eq(Encoding::BINARY)
      end
    end

    context "when given a SPNEGO NegTokenInit without mechToken (bare mechTypes list)" do
      let(:token) { build_neg_token_init_bare }

      it "returns nil (no NTLM payload to extract)" do
        result = described_class.unwrap(token)
        expect(result).to be_nil
      end
    end

    context "when given a SPNEGO NegTokenResp (0xa1 context tag)" do
      let(:ntlm_payload) { build_type3_bytes }
      let(:token) { build_neg_token_resp(ntlm_payload) }

      it "extracts the NTLM payload from the responseToken" do
        result = described_class.unwrap(token)
        expect(result).to eq(ntlm_payload)
      end
    end

    context "when given nil or empty input" do
      it "returns nil for nil input" do
        expect(described_class.unwrap(nil)).to be_nil
      end

      it "returns nil for empty binary" do
        expect(described_class.unwrap("".b)).to be_nil
      end
    end

    context "when given a malformed token" do
      it "returns nil without raising" do
        expect { described_class.unwrap("\xFF\x00\x01".b) }.not_to raise_error
        expect(described_class.unwrap("\xFF\x00\x01".b)).to be_nil
      end
    end
  end

  # ── .wrap_challenge ──────────────────────────────────────────────────────────

  describe ".wrap_challenge" do
    let(:ntlm_type2_bytes) { "NTLMSSP\x00\x02fake_challenge_data".b }

    subject(:token) { described_class.wrap_challenge(ntlm_type2_bytes) }

    it "returns binary data" do
      expect(token.encoding).to eq(Encoding::BINARY)
    end

    it "starts with NegTokenResp context tag 0xa1" do
      expect(token[0].ord).to eq(0xa1)
    end

    it "contains the NTLM Type2 bytes" do
      expect(token).to include(ntlm_type2_bytes)
    end

    it "can be round-tripped (unwrap extracts the original bytes)" do
      extracted = described_class.unwrap(token)
      expect(extracted).to eq(ntlm_type2_bytes)
    end

    it "is non-empty" do
      expect(token.bytesize).to be > 10
    end
  end

  # ── .wrap_accept_completed ───────────────────────────────────────────────────

  describe ".wrap_accept_completed" do
    subject(:token) { described_class.wrap_accept_completed }

    it "returns binary data" do
      expect(token.encoding).to eq(Encoding::BINARY)
    end

    it "starts with NegTokenResp context tag 0xa1" do
      expect(token[0].ord).to eq(0xa1)
    end

    it "is non-empty" do
      expect(token.bytesize).to be > 4
    end
  end

  # ── Helpers ─────────────────────────────────────────────────────────────────

  # Minimal NTLM Type 1 bytes
  def build_type1_bytes
    "NTLMSSP\x00\x01\x00\x00\x00fake_type1_data_here".b
  end

  # Minimal NTLM Type 3 bytes
  def build_type3_bytes
    "NTLMSSP\x00\x03\x00\x00\x00fake_type3_data_here".b
  end

  # DER helpers
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

  # Build a NegTokenInit (GSS-API APPLICATION [0] wrapper) containing mechToken with NTLM payload
  def build_neg_token_init_with_mech_token(ntlm_payload)
    # NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
    ntlmssp_oid = "\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a".b
    # SPNEGO OID: 1.3.6.1.5.5.2
    spnego_oid = "\x06\x06\x2b\x06\x01\x05\x05\x02".b

    # mechTypes = SEQUENCE { OID }
    mech_types = der_tlv(0x30, ntlmssp_oid)
    mech_types_ctx = der_tlv(0xa0, mech_types)

    # mechToken = OCTET STRING { ntlm_payload }
    octet_string = der_tlv(0x04, ntlm_payload)
    mech_token_ctx = der_tlv(0xa2, octet_string)

    # NegTokenInit SEQUENCE
    neg_init_seq = der_tlv(0x30, mech_types_ctx + mech_token_ctx)
    # [0] NegTokenInit
    neg_init_ctx = der_tlv(0xa0, neg_init_seq)

    # APPLICATION [0] { SPNEGO OID + NegTokenInit }
    application_content = spnego_oid + neg_init_ctx
    der_tlv(0x60, application_content)
  end

  # Build a NegTokenInit without mechToken (just mechTypes list)
  def build_neg_token_init_bare
    ntlmssp_oid = "\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a".b
    spnego_oid = "\x06\x06\x2b\x06\x01\x05\x05\x02".b

    mech_types = der_tlv(0x30, ntlmssp_oid)
    mech_types_ctx = der_tlv(0xa0, mech_types)
    neg_init_seq = der_tlv(0x30, mech_types_ctx)
    neg_init_ctx = der_tlv(0xa0, neg_init_seq)

    application_content = spnego_oid + neg_init_ctx
    der_tlv(0x60, application_content)
  end

  # Build a NegTokenResp containing responseToken with NTLM payload (like client's Round 2)
  def build_neg_token_resp(ntlm_payload)
    octet_string = der_tlv(0x04, ntlm_payload)
    response_token_ctx = der_tlv(0xa2, octet_string)
    sequence = der_tlv(0x30, response_token_ctx)
    der_tlv(0xa1, sequence)
  end
end
