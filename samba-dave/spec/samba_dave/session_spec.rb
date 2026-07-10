# frozen_string_literal: true

require "spec_helper"
require "samba_dave/session"
require "samba_dave/tree_connect"

RSpec.describe SambaDave::Session do
  let(:session_id) { 0x0000000000000001 }

  describe "#initialize" do
    it "stores the session_id" do
      session = described_class.new(session_id: session_id)
      expect(session.session_id).to eq(session_id)
    end

    it "is not authenticated by default" do
      session = described_class.new(session_id: session_id)
      expect(session.authenticated?).to be false
    end

    it "has no user_identity by default" do
      session = described_class.new(session_id: session_id)
      expect(session.user_identity).to be_nil
    end

    it "has no session_key by default" do
      session = described_class.new(session_id: session_id)
      expect(session.session_key).to be_nil
    end
  end

  describe "#authenticate!" do
    let(:identity) { { username: "testuser" } }

    it "marks the session as authenticated" do
      session = described_class.new(session_id: session_id)
      session.authenticate!(identity)
      expect(session.authenticated?).to be true
    end

    it "stores the user_identity" do
      session = described_class.new(session_id: session_id)
      session.authenticate!(identity)
      expect(session.user_identity).to eq(identity)
    end

    it "returns self for chaining" do
      session = described_class.new(session_id: session_id)
      result = session.authenticate!(identity)
      expect(result).to be(session)
    end
  end

  describe "#session_key=" do
    it "stores the session key" do
      session = described_class.new(session_id: session_id)
      session.session_key = "some_key"
      expect(session.session_key).to eq("some_key")
    end
  end

  describe "#set_session_key" do
    it "stores the session key" do
      session = described_class.new(session_id: session_id)
      session.set_session_key("k" * 16)
      expect(session.session_key).to eq("k" * 16)
    end

    it "uses the raw 16-byte session key as the SMB 2.x signing key (no KDF)" do
      # For dialects 2.0.2/2.1, Session.SigningKey == Session.SessionKey.
      session = described_class.new(session_id: session_id)
      key = ["270E1BA896585EEB7AF3472D3B4C75A7"].pack("H*")
      session.set_session_key(key)
      expect(session.signing_key).to eq(key)
    end

    it "zero-pads a short session key to 16 bytes for signing" do
      session = described_class.new(session_id: session_id)
      session.set_session_key("abc")
      expect(session.signing_key.bytesize).to eq(16)
      expect(session.signing_key).to eq("abc".b + ("\x00".b * 13))
    end

    it "leaves signing_key nil when the key is nil" do
      session = described_class.new(session_id: session_id)
      session.set_session_key(nil)
      expect(session.signing_key).to be_nil
      expect(session.signing_algorithm).to be_nil
    end

    it "selects HMAC-SHA256 for an SMB 2.x session" do
      session = described_class.new(session_id: session_id)
      session.set_session_key("k" * 16, dialect: SambaDave::Protocol::Constants::Dialects::SMB2_1)
      expect(session.signing_key).to eq("k" * 16)
      expect(session.signing_algorithm).to eq(:hmac_sha256)
    end

    context "for an SMB 3.0 session" do
      # MS known-answer vector: SessionKey 7CD4… → SigningKey 0B7E…
      let(:session_key) { ["7CD451825D0450D235424E44BA6E78CC"].pack("H*") }

      it "derives the signing key via the SMB3 KDF and selects AES-CMAC" do
        session = described_class.new(session_id: session_id)
        session.set_session_key(session_key, dialect: SambaDave::Protocol::Constants::Dialects::SMB3_0)
        expect(session.signing_key.unpack1("H*").upcase).to eq("0B7E9C5CAC36C0F6EA9AB275298CEDCE")
        expect(session.signing_algorithm).to eq(:aes_cmac)
      end
    end
  end

  describe "with multiple sessions" do
    it "each session has its own state" do
      s1 = described_class.new(session_id: 1)
      s2 = described_class.new(session_id: 2)

      s1.authenticate!({ username: "alice" })

      expect(s1.authenticated?).to be true
      expect(s2.authenticated?).to be false
      expect(s1.user_identity[:username]).to eq("alice")
    end
  end

  describe "tree connect management" do
    let(:session) { described_class.new(session_id: session_id) }
    let(:fs)      { double("FileSystemProvider") }

    def make_tc(id)
      SambaDave::TreeConnect.new(tree_id: id, share_name: "share", filesystem: fs)
    end

    describe "#allocate_tree_id" do
      it "returns non-zero integer" do
        expect(session.allocate_tree_id).to be > 0
      end

      it "returns a different value on each call" do
        id1 = session.allocate_tree_id
        id2 = session.allocate_tree_id
        expect(id1).not_to eq(id2)
      end
    end

    describe "#add_tree_connect / #find_tree_connect" do
      it "stores and retrieves a TreeConnect by tree_id" do
        tc = make_tc(42)
        session.add_tree_connect(tc)
        expect(session.find_tree_connect(42)).to eq(tc)
      end

      it "returns nil for an unknown tree_id" do
        expect(session.find_tree_connect(99)).to be_nil
      end
    end

    describe "#remove_tree_connect" do
      it "removes the TreeConnect so find returns nil" do
        tc = make_tc(5)
        session.add_tree_connect(tc)
        session.remove_tree_connect(5)
        expect(session.find_tree_connect(5)).to be_nil
      end

      it "silently ignores unknown tree_ids" do
        expect { session.remove_tree_connect(999) }.not_to raise_error
      end
    end

    it "can hold multiple tree connects simultaneously" do
      tc1 = make_tc(1)
      tc2 = make_tc(2)
      session.add_tree_connect(tc1)
      session.add_tree_connect(tc2)
      expect(session.find_tree_connect(1)).to eq(tc1)
      expect(session.find_tree_connect(2)).to eq(tc2)
    end
  end
end
