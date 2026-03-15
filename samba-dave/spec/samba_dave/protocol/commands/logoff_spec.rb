# frozen_string_literal: true

require "spec_helper"
require "samba_dave/session"
require "samba_dave/protocol/commands/logoff"

RSpec.describe SambaDave::Protocol::Commands::Logoff do
  let(:session_id) { 0x0000000000000001 }

  def build_logoff_request
    # LogoffRequest: StructureSize(2) + Reserved(2) = 4 bytes
    [4, 0].pack("S<S<")
  end

  # ── BinData structures ───────────────────────────────────────────────────────

  describe "LogoffRequest" do
    subject(:klass) { SambaDave::Protocol::Commands::LogoffRequest }

    it "parses structure_size as 4" do
      req = klass.read(build_logoff_request)
      expect(req.structure_size).to eq(4)
    end
  end

  describe "LogoffResponse" do
    subject(:klass) { SambaDave::Protocol::Commands::LogoffResponse }

    it "has structure_size of 4" do
      resp = klass.new
      expect(resp.structure_size).to eq(4)
    end

    it "serialises to 4 bytes" do
      resp = klass.new
      expect(resp.to_binary_s.bytesize).to eq(4)
    end
  end

  # ── .handle ──────────────────────────────────────────────────────────────────

  describe ".handle" do
    let(:identity)   { { username: "testuser" } }
    let(:session)    { SambaDave::Session.new(session_id: session_id).tap { |s| s.authenticate!(identity) } }
    let(:sessions)   { { session_id => session } }

    subject(:result) do
      described_class.handle(build_logoff_request, session_id: session_id, sessions: sessions)
    end

    it "returns STATUS_SUCCESS" do
      expect(result[:status]).to eq(SambaDave::Protocol::Constants::Status::SUCCESS)
    end

    it "returns a body" do
      expect(result[:body]).not_to be_nil
      expect(result[:body].bytesize).to be > 0
    end

    it "removes the session from the sessions hash" do
      described_class.handle(build_logoff_request, session_id: session_id, sessions: sessions)
      expect(sessions.key?(session_id)).to be false
    end

    context "when session does not exist" do
      let(:sessions) { {} }

      it "still returns STATUS_SUCCESS" do
        result = described_class.handle(build_logoff_request, session_id: session_id, sessions: sessions)
        expect(result[:status]).to eq(SambaDave::Protocol::Constants::Status::SUCCESS)
      end
    end
  end
end
