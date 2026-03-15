# frozen_string_literal: true

require "spec_helper"
require "samba_dave/session"

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
end
