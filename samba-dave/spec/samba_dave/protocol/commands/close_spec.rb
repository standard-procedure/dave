# frozen_string_literal: true

require "spec_helper"
require "dave/resource"
require "samba_dave/tree_connect"
require "samba_dave/open_file"
require "samba_dave/open_file_table"
require "samba_dave/protocol/commands/close"

RSpec.describe SambaDave::Protocol::Commands::Close do
  C = SambaDave::Protocol::Constants

  let(:filesystem)      { double("FileSystemProvider") }
  let(:tree_connect)    { SambaDave::TreeConnect.new(tree_id: 1, share_name: "s", filesystem: filesystem) }
  let(:open_file_table) { SambaDave::OpenFileTable.new }

  def make_open_file(is_directory: false)
    fid = open_file_table.generate_file_id
    of  = SambaDave::OpenFile.new(
      file_id_bytes: fid,
      path:          is_directory ? "/dir/" : "/file.txt",
      is_directory:  is_directory,
      tree_connect:  tree_connect
    )
    open_file_table.add(of)
    of
  end

  # Build CLOSE request body (24 bytes):
  #   StructureSize (2) = 24
  #   Flags (2) — 0x0001 = POSTQUERY_ATTRIB
  #   Reserved (4)
  #   FileId (16 bytes = two uint64)
  def build_close_body(file_id_bytes, flags: 0)
    persistent = file_id_bytes[0, 8].unpack1("Q<")
    volatile   = file_id_bytes[8, 8].unpack1("Q<")
    [24, flags, 0, persistent, volatile].pack("S<S<L<Q<Q<")
  end

  describe ".handle — valid FileId" do
    it "returns STATUS_SUCCESS" do
      of     = make_open_file
      result = described_class.handle(build_close_body(of.file_id_bytes),
                                      open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "removes the file from the open_file_table" do
      of = make_open_file
      described_class.handle(build_close_body(of.file_id_bytes),
                             open_file_table: open_file_table)
      expect(open_file_table.get(of.file_id_bytes)).to be_nil
    end

    it "returns a 60-byte response body" do
      of     = make_open_file
      result = described_class.handle(build_close_body(of.file_id_bytes),
                                      open_file_table: open_file_table)
      expect(result[:body].bytesize).to eq(60)
    end

    it "returns StructureSize=60 in the response" do
      of       = make_open_file
      result   = described_class.handle(build_close_body(of.file_id_bytes),
                                        open_file_table: open_file_table)
      response = SambaDave::Protocol::Commands::CloseResponse.read(result[:body])
      expect(response.structure_size).to eq(60)
    end

    context "without POSTQUERY_ATTRIB flag" do
      it "returns zero timestamps and attributes" do
        of       = make_open_file
        result   = described_class.handle(build_close_body(of.file_id_bytes, flags: 0),
                                          open_file_table: open_file_table)
        response = SambaDave::Protocol::Commands::CloseResponse.read(result[:body])
        expect(response.creation_time).to eq(0)
        expect(response.file_attributes).to eq(0)
      end
    end

    context "with POSTQUERY_ATTRIB flag (0x0001)" do
      let(:now) { Time.now }
      let(:resource) do
        Dave::Resource.new(
          path: "/file.txt", collection: false,
          content_type: "text/plain", content_length: 99,
          etag: '"e"', last_modified: now, created_at: now
        )
      end

      it "queries file attributes from the filesystem and includes them in response" do
        allow(filesystem).to receive(:get_resource).and_return(resource)
        of       = make_open_file
        result   = described_class.handle(build_close_body(of.file_id_bytes, flags: 0x0001),
                                          open_file_table: open_file_table)
        response = SambaDave::Protocol::Commands::CloseResponse.read(result[:body])
        expect(response.end_of_file).to eq(99)
        expect(response.file_attributes).not_to eq(0)
      end
    end
  end

  describe ".handle — invalid FileId" do
    it "returns STATUS_INVALID_HANDLE for an unknown FileId" do
      unknown_id = open_file_table.generate_file_id
      result     = described_class.handle(build_close_body(unknown_id),
                                          open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::INVALID_HANDLE)
    end
  end

  describe ".handle — delete-on-close" do
    it "calls filesystem.delete when delete_on_close is set" do
      allow(filesystem).to receive(:delete)
      of              = make_open_file
      of.delete_on_close = true
      described_class.handle(build_close_body(of.file_id_bytes),
                             open_file_table: open_file_table)
      expect(filesystem).to have_received(:delete).with(of.path)
    end

    it "does NOT call filesystem.delete when delete_on_close is false" do
      expect(filesystem).not_to receive(:delete)
      of = make_open_file
      described_class.handle(build_close_body(of.file_id_bytes),
                             open_file_table: open_file_table)
    end

    it "still removes the handle from the table even if delete raises" do
      allow(filesystem).to receive(:delete).and_raise(StandardError, "oops")
      of              = make_open_file
      of.delete_on_close = true
      expect {
        described_class.handle(build_close_body(of.file_id_bytes),
                               open_file_table: open_file_table)
      }.not_to raise_error
      expect(open_file_table.get(of.file_id_bytes)).to be_nil
    end
  end
end
