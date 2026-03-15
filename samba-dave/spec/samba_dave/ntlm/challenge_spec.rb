# frozen_string_literal: true

require "spec_helper"
require "net/ntlm"
require "samba_dave/ntlm/spnego"
require "samba_dave/ntlm/challenge"

RSpec.describe SambaDave::NTLM::Challenge do
  # Fixed test data
  let(:server_challenge) { "\x01\x02\x03\x04\x05\x06\x07\x08".b }
  let(:username)         { "testuser" }
  let(:password)         { "testpass" }

  # ── .build ──────────────────────────────────────────────────────────────────

  describe ".build" do
    subject(:type2_bytes) { described_class.build(server_challenge: server_challenge) }

    it "returns binary data" do
      expect(type2_bytes.encoding).to eq(Encoding::BINARY)
    end

    it "starts with NTLMSSP signature" do
      expect(type2_bytes[0, 8]).to eq("NTLMSSP\x00".b)
    end

    it "contains message type 2 at offset 8" do
      # Type2 = 0x00000002 (little-endian)
      expect(type2_bytes[8, 4]).to eq("\x02\x00\x00\x00".b)
    end

    it "includes the server challenge bytes" do
      expect(type2_bytes).to include(server_challenge)
    end

    it "can be parsed by rubyntlm" do
      msg = Net::NTLM::Message.parse(type2_bytes)
      expect(msg).to be_a(Net::NTLM::Message::Type2)
    end

    it "is non-empty" do
      expect(type2_bytes.bytesize).to be > 32
    end

    context "with a target_name" do
      subject(:type2_bytes) do
        described_class.build(server_challenge: server_challenge, target_name: "WORKGROUP")
      end

      it "can still be parsed by rubyntlm" do
        msg = Net::NTLM::Message.parse(type2_bytes)
        expect(msg).to be_a(Net::NTLM::Message::Type2)
      end
    end
  end

  # ── .validate ───────────────────────────────────────────────────────────────

  describe ".validate" do
    # Use rubyntlm to build a real Type3 (AUTHENTICATE) message for testing
    let(:type2_bytes) do
      described_class.build(server_challenge: server_challenge)
    end

    let(:type3_bytes) do
      t2 = Net::NTLM::Message.parse(type2_bytes)
      t3 = t2.response(
        { user: username, password: password, domain: "" },
        { ntlmv2: true }
      )
      t3.serialize
    end

    context "with correct credentials" do
      it "returns the username" do
        result = described_class.validate(
          type3_bytes,
          server_challenge: server_challenge,
          password: password
        )
        expect(result).to eq(username)
      end
    end

    context "with incorrect password" do
      it "returns nil" do
        result = described_class.validate(
          type3_bytes,
          server_challenge: server_challenge,
          password: "wrongpassword"
        )
        expect(result).to be_nil
      end
    end

    context "with an empty password" do
      let(:password) { "" }
      let(:type3_bytes) do
        t2 = Net::NTLM::Message.parse(type2_bytes)
        t3 = t2.response(
          { user: username, password: "", domain: "" },
          { ntlmv2: true }
        )
        t3.serialize
      end

      it "validates correctly for empty password" do
        result = described_class.validate(
          type3_bytes,
          server_challenge: server_challenge,
          password: ""
        )
        expect(result).to eq(username)
      end

      it "returns nil when wrong password provided for empty-password account" do
        result = described_class.validate(
          type3_bytes,
          server_challenge: server_challenge,
          password: "notblank"
        )
        expect(result).to be_nil
      end
    end

    context "with nil or malformed Type3" do
      it "returns nil for nil input" do
        result = described_class.validate(nil, server_challenge: server_challenge, password: password)
        expect(result).to be_nil
      end

      it "returns nil for malformed bytes" do
        result = described_class.validate("garbage".b, server_challenge: server_challenge, password: password)
        expect(result).to be_nil
      end
    end

    context "with different server challenges" do
      it "returns nil when validated with a different server_challenge" do
        wrong_challenge = "\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8".b
        result = described_class.validate(
          type3_bytes,
          server_challenge: wrong_challenge,
          password: password
        )
        expect(result).to be_nil
      end
    end
  end
end
