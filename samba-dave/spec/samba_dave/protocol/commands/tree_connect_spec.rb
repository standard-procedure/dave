# frozen_string_literal: true

require "spec_helper"
require "samba_dave/session"
require "samba_dave/tree_connect"
require "samba_dave/protocol/commands/tree_connect"

RSpec.describe SambaDave::Protocol::Commands::TreeConnectCmd do
  C = SambaDave::Protocol::Constants unless defined?(C)

  let(:filesystem) { double("FileSystemProvider") }
  let(:server)     { double("Server", share_name: "myshare", filesystem: filesystem) }
  let(:session)    { SambaDave::Session.new(session_id: 1) }

  # Build a raw TREE_CONNECT request body for the given UNC path.
  def build_body(unc_path)
    path_bytes   = unc_path.encode("UTF-16LE").b
    path_offset  = 64 + 8  # SMB2 header (64) + fixed structure (8)
    path_length  = path_bytes.bytesize
    [9, 0, path_offset, path_length].pack("S<S<S<S<") + path_bytes
  end

  describe ".handle — valid share" do
    it "returns STATUS_SUCCESS" do
      result = described_class.handle(build_body("\\\\server\\myshare"),
                                      session: session, server: server)
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "returns a TreeConnect response body with ShareType=DISK (0x01)" do
      described_class.handle(build_body("\\\\server\\myshare"),
                             session: session, server: server)
      result = described_class.handle(build_body("\\\\server\\myshare"),
                                      session: session, server: server)
      response = SambaDave::Protocol::Commands::TreeConnectResponse.read(result[:body])
      expect(response.share_type).to eq(0x01)
    end

    it "returns StructureSize=16" do
      result = described_class.handle(build_body("\\\\server\\myshare"),
                                      session: session, server: server)
      response = SambaDave::Protocol::Commands::TreeConnectResponse.read(result[:body])
      expect(response.structure_size).to eq(16)
    end

    it "includes a positive response_tree_id" do
      result = described_class.handle(build_body("\\\\server\\myshare"),
                                      session: session, server: server)
      expect(result[:response_tree_id]).to be > 0
    end

    it "registers the tree connect in the session" do
      result = described_class.handle(build_body("\\\\server\\myshare"),
                                      session: session, server: server)
      tree_id = result[:response_tree_id]
      tc = session.find_tree_connect(tree_id)
      expect(tc).not_to be_nil
      expect(tc.share_name).to eq("myshare")
      expect(tc.filesystem).to eq(filesystem)
    end

    it "is case-insensitive for share name matching" do
      result = described_class.handle(build_body("\\\\server\\MYSHARE"),
                                      session: session, server: server)
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "allocates different tree_ids for multiple connects" do
      r1 = described_class.handle(build_body("\\\\server\\myshare"),
                                  session: session, server: server)
      r2 = described_class.handle(build_body("\\\\server\\myshare"),
                                  session: session, server: server)
      expect(r1[:response_tree_id]).not_to eq(r2[:response_tree_id])
    end
  end

  describe ".handle — unknown share" do
    it "returns STATUS_BAD_NETWORK_NAME" do
      result = described_class.handle(build_body("\\\\server\\wrongshare"),
                                      session: session, server: server)
      expect(result[:status]).to eq(C::Status::BAD_NETWORK_NAME)
    end

    it "does not register a tree connect" do
      described_class.handle(build_body("\\\\server\\wrongshare"),
                             session: session, server: server)
      # session should have no tree connects
      expect(session.find_tree_connect(1)).to be_nil
    end
  end
end

RSpec.describe SambaDave::Protocol::Commands::TreeDisconnectCmd do
  C = SambaDave::Protocol::Constants unless defined?(C)

  let(:filesystem) { double("FileSystemProvider") }
  let(:session)    { SambaDave::Session.new(session_id: 1) }

  def add_tree_connect(tree_id)
    tc = SambaDave::TreeConnect.new(tree_id: tree_id, share_name: "share", filesystem: filesystem)
    session.add_tree_connect(tc)
    tree_id
  end

  def build_disconnect_body
    # StructureSize=4, Reserved=0
    [4, 0].pack("S<S<")
  end

  describe ".handle" do
    it "returns STATUS_SUCCESS" do
      tree_id = add_tree_connect(5)
      result = described_class.handle(build_disconnect_body, session: session, tree_id: tree_id)
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "removes the tree connect from the session" do
      tree_id = add_tree_connect(5)
      described_class.handle(build_disconnect_body, session: session, tree_id: tree_id)
      expect(session.find_tree_connect(tree_id)).to be_nil
    end

    it "returns STATUS_SUCCESS even for unknown tree_id" do
      result = described_class.handle(build_disconnect_body, session: session, tree_id: 999)
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "returns a 4-byte response body" do
      result = described_class.handle(build_disconnect_body, session: session, tree_id: 1)
      expect(result[:body].bytesize).to eq(4)
    end
  end
end
