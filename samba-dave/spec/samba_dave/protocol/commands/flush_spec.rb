# frozen_string_literal: true

require "spec_helper"
require "samba_dave/tree_connect"
require "samba_dave/open_file"
require "samba_dave/open_file_table"
require "samba_dave/protocol/commands/flush"

RSpec.describe SambaDave::Protocol::Commands::Flush do
  C = SambaDave::Protocol::Constants

  let(:filesystem)      { double("FileSystemProvider") }
  let(:tree_connect)    { SambaDave::TreeConnect.new(tree_id: 1, share_name: "s", filesystem: filesystem) }
  let(:open_file_table) { SambaDave::OpenFileTable.new }

  def make_open_file
    fid = open_file_table.generate_file_id
    of  = SambaDave::OpenFile.new(
      file_id_bytes: fid,
      path:          "/file.txt",
      is_directory:  false,
      tree_connect:  tree_connect
    )
    open_file_table.add(of)
    of
  end

  # Build FLUSH request body (24 bytes):
  #   StructureSize(2) Reserved1(2) Reserved2(4)
  #   FileId.Persistent(8) FileId.Volatile(8)
  def build_flush_body(file_id_bytes)
    persistent = file_id_bytes[0, 8].unpack1("Q<")
    volatile   = file_id_bytes[8, 8].unpack1("Q<")
    [24, 0, 0, persistent, volatile].pack("S<S<L<Q<Q<")
  end

  describe ".handle — valid FileId" do
    it "returns STATUS_SUCCESS" do
      of     = make_open_file
      result = described_class.handle(build_flush_body(of.file_id_bytes),
                                      open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "returns a 4-byte response body (StructureSize=4 + Reserved=0)" do
      of     = make_open_file
      result = described_class.handle(build_flush_body(of.file_id_bytes),
                                      open_file_table: open_file_table)
      expect(result[:body].bytesize).to eq(4)
    end

    it "returns StructureSize=4 in the response" do
      of       = make_open_file
      result   = described_class.handle(build_flush_body(of.file_id_bytes),
                                        open_file_table: open_file_table)
      response = SambaDave::Protocol::Commands::FlushResponse.read(result[:body])
      expect(response.structure_size).to eq(4)
    end

    it "does not touch the filesystem (provider is synchronous)" do
      expect(filesystem).not_to receive(:write_content)
      of = make_open_file
      described_class.handle(build_flush_body(of.file_id_bytes),
                             open_file_table: open_file_table)
    end
  end

  describe ".handle — invalid FileId" do
    it "returns STATUS_INVALID_HANDLE for an unknown FileId" do
      unknown_id = open_file_table.generate_file_id
      result     = described_class.handle(build_flush_body(unknown_id),
                                          open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::INVALID_HANDLE)
    end
  end
end
