# frozen_string_literal: true

require "spec_helper"
require "samba_dave/tree_connect"
require "samba_dave/open_file"
require "samba_dave/open_file_table"

RSpec.describe SambaDave::OpenFile do
  let(:filesystem)    { double("FileSystemProvider") }
  let(:tree_connect)  { SambaDave::TreeConnect.new(tree_id: 1, share_name: "s", filesystem: filesystem) }
  let(:file_id_bytes) { SecureRandom.bytes(16) }

  describe "#initialize" do
    it "stores file_id_bytes" do
      of = described_class.new(file_id_bytes: file_id_bytes, path: "/foo.txt",
                                is_directory: false, tree_connect: tree_connect)
      expect(of.file_id_bytes).to eq(file_id_bytes)
    end

    it "stores path" do
      of = described_class.new(file_id_bytes: file_id_bytes, path: "/some/path.txt",
                                is_directory: false, tree_connect: tree_connect)
      expect(of.path).to eq("/some/path.txt")
    end

    it "stores tree_connect" do
      of = described_class.new(file_id_bytes: file_id_bytes, path: "/foo.txt",
                                is_directory: false, tree_connect: tree_connect)
      expect(of.tree_connect).to eq(tree_connect)
    end

    it "defaults position to 0" do
      of = described_class.new(file_id_bytes: file_id_bytes, path: "/foo.txt",
                                is_directory: false, tree_connect: tree_connect)
      expect(of.position).to eq(0)
    end

    it "defaults enum_cursor to 0" do
      of = described_class.new(file_id_bytes: file_id_bytes, path: "/foo.txt",
                                is_directory: false, tree_connect: tree_connect)
      expect(of.enum_cursor).to eq(0)
    end
  end

  describe "#directory?" do
    it "returns true when is_directory is true" do
      of = described_class.new(file_id_bytes: file_id_bytes, path: "/dir/",
                                is_directory: true, tree_connect: tree_connect)
      expect(of.directory?).to be true
    end

    it "returns false when is_directory is false" do
      of = described_class.new(file_id_bytes: file_id_bytes, path: "/file.txt",
                                is_directory: false, tree_connect: tree_connect)
      expect(of.directory?).to be false
    end
  end

  describe "#filesystem" do
    it "delegates to tree_connect" do
      of = described_class.new(file_id_bytes: file_id_bytes, path: "/foo.txt",
                                is_directory: false, tree_connect: tree_connect)
      expect(of.filesystem).to eq(filesystem)
    end
  end

  describe "#position=" do
    it "allows updating position" do
      of = described_class.new(file_id_bytes: file_id_bytes, path: "/foo.txt",
                                is_directory: false, tree_connect: tree_connect)
      of.position = 1024
      expect(of.position).to eq(1024)
    end
  end

  describe "#enum_cursor=" do
    it "allows updating enum_cursor" do
      of = described_class.new(file_id_bytes: file_id_bytes, path: "/dir/",
                                is_directory: true, tree_connect: tree_connect)
      of.enum_cursor = 5
      expect(of.enum_cursor).to eq(5)
    end
  end

  describe "#delete_on_close" do
    it "defaults to false" do
      of = described_class.new(file_id_bytes: file_id_bytes, path: "/foo.txt",
                                is_directory: false, tree_connect: tree_connect)
      expect(of.delete_on_close).to be false
    end

    it "can be set to true" do
      of = described_class.new(file_id_bytes: file_id_bytes, path: "/foo.txt",
                                is_directory: false, tree_connect: tree_connect)
      of.delete_on_close = true
      expect(of.delete_on_close).to be true
    end
  end
end

RSpec.describe SambaDave::OpenFileTable do
  let(:filesystem)   { double("FileSystemProvider") }
  let(:tree_connect) { SambaDave::TreeConnect.new(tree_id: 1, share_name: "s", filesystem: filesystem) }

  def make_open_file(table)
    fid = table.generate_file_id
    SambaDave::OpenFile.new(file_id_bytes: fid, path: "/foo.txt",
                             is_directory: false, tree_connect: tree_connect)
  end

  describe "#generate_file_id" do
    it "returns exactly 16 bytes" do
      table = described_class.new
      expect(table.generate_file_id.bytesize).to eq(16)
    end

    it "returns unique IDs each call" do
      table = described_class.new
      ids = Array.new(10) { table.generate_file_id }
      expect(ids.uniq.size).to eq(10)
    end
  end

  describe "#add and #get" do
    it "stores and retrieves an OpenFile by file_id_bytes" do
      table = described_class.new
      of    = make_open_file(table)
      table.add(of)
      expect(table.get(of.file_id_bytes)).to eq(of)
    end

    it "returns nil for an unknown file_id" do
      table = described_class.new
      expect(table.get(SecureRandom.bytes(16))).to be_nil
    end
  end

  describe "#remove" do
    it "removes an OpenFile so get returns nil" do
      table = described_class.new
      of    = make_open_file(table)
      table.add(of)
      table.remove(of.file_id_bytes)
      expect(table.get(of.file_id_bytes)).to be_nil
    end

    it "silently ignores removal of an unknown file_id" do
      table = described_class.new
      expect { table.remove(SecureRandom.bytes(16)) }.not_to raise_error
    end
  end

  describe "#size" do
    it "tracks the number of open files" do
      table = described_class.new
      of    = make_open_file(table)
      expect(table.size).to eq(0)
      table.add(of)
      expect(table.size).to eq(1)
      table.remove(of.file_id_bytes)
      expect(table.size).to eq(0)
    end
  end
end
