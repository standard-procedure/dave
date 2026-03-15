# frozen_string_literal: true

require "spec_helper"

RSpec.describe SambaDave::Server do
  let(:filesystem) { instance_double("Dave::FileSystemInterface") }

  describe "#initialize" do
    it "creates a server with required parameters" do
      server = described_class.new(filesystem: filesystem)

      expect(server.share_name).to eq("share")
      expect(server.port).to eq(445)
      expect(server.server_guid).to be_a(String)
      expect(server.server_guid.bytesize).to eq(16)
    end

    it "accepts custom share name and port" do
      server = described_class.new(
        filesystem: filesystem,
        share_name: "documents",
        port: 4450
      )

      expect(server.share_name).to eq("documents")
      expect(server.port).to eq(4450)
    end

    it "generates a unique server GUID" do
      server1 = described_class.new(filesystem: filesystem)
      server2 = described_class.new(filesystem: filesystem)

      expect(server1.server_guid).not_to eq(server2.server_guid)
    end
  end

  # TODO: Phase 1 — test TCP accept loop, negotiate handling, connection lifecycle
end
