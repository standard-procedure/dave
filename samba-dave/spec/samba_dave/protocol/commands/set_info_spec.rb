# frozen_string_literal: true

require "spec_helper"
require "stringio"
require "dave/resource"
require "samba_dave/tree_connect"
require "samba_dave/open_file"
require "samba_dave/open_file_table"
require "samba_dave/protocol/commands/set_info"

RSpec.describe SambaDave::Protocol::Commands::SetInfo do
  C = SambaDave::Protocol::Constants

  let(:filesystem)      { double("FileSystemProvider") }
  let(:tree_connect)    { SambaDave::TreeConnect.new(tree_id: 1, share_name: "s", filesystem: filesystem) }
  let(:open_file_table) { SambaDave::OpenFileTable.new }

  def make_open_file(is_directory: false, path: "/file.txt")
    fid = open_file_table.generate_file_id
    of  = SambaDave::OpenFile.new(
      file_id_bytes: fid,
      path:          path,
      is_directory:  is_directory,
      tree_connect:  tree_connect
    )
    open_file_table.add(of)
    of
  end

  # Build a SET_INFO request body.
  # Fixed structure (32 bytes):
  #   StructureSize(2) InfoType(1) FileInformationClass(1)
  #   BufferLength(4) BufferOffset(2) Reserved(2)
  #   AdditionalInformation(4)
  #   FileId.Persistent(8) FileId.Volatile(8)
  # + buffer
  #
  # BufferOffset = 64 (SMB2 header) + 32 (fixed body) = 96
  # Build a SET_INFO request body.
  # Fixed structure (32 bytes, per MS-SMB2 section 2.2.39):
  #   StructureSize(2)  InfoType(1)  FileInformationClass(1)
  #   BufferLength(4)   BufferOffset(2)  Reserved(2)
  #   AdditionalInformation(4)
  #   FileId.Persistent(8)  FileId.Volatile(8)
  # + buffer
  #
  # BufferOffset = 64 (SMB2 header) + 32 (fixed body) = 96
  def build_set_info_body(file_id_bytes, info_type:, info_class:, buffer:)
    persistent    = file_id_bytes[0, 8].unpack1("Q<")
    volatile      = file_id_bytes[8, 8].unpack1("Q<")
    buffer_offset = 96  # 64 header + 32 fixed body
    # S< C C L< S< S< L< Q< Q<
    fixed = [33, info_type, info_class, buffer.bytesize,
             buffer_offset, 0, 0, persistent, volatile].pack("S<CCL<S<S<L<Q<Q<")
    fixed.b + buffer.b
  end

  describe ".handle — invalid handle" do
    it "returns STATUS_INVALID_HANDLE for an unknown FileId" do
      unknown_id = open_file_table.generate_file_id
      buf    = [0].pack("L<")  # dummy FileBasicInformation
      result = described_class.handle(
        build_set_info_body(unknown_id, info_type: 1, info_class: 0x04, buffer: buf),
        open_file_table: open_file_table
      )
      expect(result[:status]).to eq(C::Status::INVALID_HANDLE)
    end
  end

  describe ".handle — FileBasicInformation (0x04)" do
    it "returns STATUS_SUCCESS (no-op — timestamps are provider-managed)" do
      # FileBasicInformation: 8*4 (timestamps) + 4 (attrs) + 4 (reserved) = 40 bytes
      timestamps = Array.new(4, 0).pack("Q<Q<Q<Q<")
      buf        = timestamps + [0, 0].pack("L<L<")
      of         = make_open_file

      result = described_class.handle(
        build_set_info_body(of.file_id_bytes, info_type: 1, info_class: 0x04, buffer: buf),
        open_file_table: open_file_table
      )
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "returns a 2-byte response body" do
      timestamps = Array.new(4, 0).pack("Q<Q<Q<Q<")
      buf        = timestamps + [0, 0].pack("L<L<")
      of         = make_open_file

      result = described_class.handle(
        build_set_info_body(of.file_id_bytes, info_type: 1, info_class: 0x04, buffer: buf),
        open_file_table: open_file_table
      )
      expect(result[:body].bytesize).to eq(2)
    end
  end

  describe ".handle — FileDispositionInformation (0x0D)" do
    it "sets delete_on_close = true when buffer byte is 1" do
      buf = [1].pack("C")
      of  = make_open_file

      described_class.handle(
        build_set_info_body(of.file_id_bytes, info_type: 1, info_class: 0x0D, buffer: buf),
        open_file_table: open_file_table
      )
      expect(of.delete_on_close).to be true
    end

    it "sets delete_on_close = false when buffer byte is 0" do
      buf = [0].pack("C")
      of  = make_open_file
      of.delete_on_close = true

      described_class.handle(
        build_set_info_body(of.file_id_bytes, info_type: 1, info_class: 0x0D, buffer: buf),
        open_file_table: open_file_table
      )
      expect(of.delete_on_close).to be false
    end

    it "returns STATUS_SUCCESS" do
      buf    = [1].pack("C")
      of     = make_open_file
      result = described_class.handle(
        build_set_info_body(of.file_id_bytes, info_type: 1, info_class: 0x0D, buffer: buf),
        open_file_table: open_file_table
      )
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end
  end

  describe ".handle — FileRenameInformation (0x0A)" do
    # FileRenameInformation (64-bit variant):
    #   ReplaceIfExists(1) Reserved(7) RootDirectory(8) FileNameLength(4) FileName(var)
    def build_rename_buffer(new_name, replace: false)
      name_utf16 = new_name.encode("UTF-16LE").b
      [replace ? 1 : 0].pack("C") +
        ("\x00" * 7) +           # Reserved (7 bytes)
        [0].pack("Q<") +         # RootDirectory (8 bytes, always 0)
        [name_utf16.bytesize].pack("L<") +
        name_utf16
    end

    it "calls provider move with correct paths and returns STATUS_SUCCESS" do
      allow(filesystem).to receive(:move)
      of     = make_open_file(path: "/old.txt")
      buf    = build_rename_buffer("/new.txt")
      result = described_class.handle(
        build_set_info_body(of.file_id_bytes, info_type: 1, info_class: 0x0A, buffer: buf),
        open_file_table: open_file_table
      )
      expect(filesystem).to have_received(:move).with("/old.txt", "/new.txt")
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "strips leading backslash from the new name" do
      allow(filesystem).to receive(:move)
      of  = make_open_file(path: "/old.txt")
      buf = build_rename_buffer("\\new.txt")
      described_class.handle(
        build_set_info_body(of.file_id_bytes, info_type: 1, info_class: 0x0A, buffer: buf),
        open_file_table: open_file_table
      )
      expect(filesystem).to have_received(:move).with("/old.txt", "/new.txt")
    end

    it "converts backslashes to forward slashes" do
      allow(filesystem).to receive(:move)
      of  = make_open_file(path: "/docs/old.txt")
      buf = build_rename_buffer("\\subdir\\new.txt")
      described_class.handle(
        build_set_info_body(of.file_id_bytes, info_type: 1, info_class: 0x0A, buffer: buf),
        open_file_table: open_file_table
      )
      expect(filesystem).to have_received(:move).with("/docs/old.txt", "/subdir/new.txt")
    end
  end

  describe ".handle — FileEndOfFileInformation (0x14)" do
    let(:content) { "Hello, World!" }

    before do
      allow(filesystem).to receive(:read_content).and_return(StringIO.new(content))
    end

    it "returns STATUS_SUCCESS" do
      allow(filesystem).to receive(:write_content)
      of     = make_open_file
      buf    = [5].pack("Q<")  # truncate to 5 bytes
      result = described_class.handle(
        build_set_info_body(of.file_id_bytes, info_type: 1, info_class: 0x14, buffer: buf),
        open_file_table: open_file_table
      )
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "truncates the file to the specified EndOfFile size" do
      written = nil
      allow(filesystem).to receive(:write_content) do |_path, io|
        written = io.read
        '"etag"'
      end
      of  = make_open_file
      buf = [5].pack("Q<")  # truncate to 5 bytes
      described_class.handle(
        build_set_info_body(of.file_id_bytes, info_type: 1, info_class: 0x14, buffer: buf),
        open_file_table: open_file_table
      )
      expect(written).to eq("Hello")
    end

    it "extends the file with zeros when EndOfFile > current size" do
      written = nil
      allow(filesystem).to receive(:write_content) do |_path, io|
        written = io.read
        '"etag"'
      end
      of  = make_open_file
      buf = [20].pack("Q<")  # extend to 20 bytes
      described_class.handle(
        build_set_info_body(of.file_id_bytes, info_type: 1, info_class: 0x14, buffer: buf),
        open_file_table: open_file_table
      )
      expect(written.bytesize).to eq(20)
      expect(written[0, content.bytesize]).to eq(content)
      expect(written[content.bytesize..]).to eq("\x00" * (20 - content.bytesize))
    end
  end

  describe ".handle — FileAllocationInformation (0x13)" do
    let(:content) { "Hello, World!" }

    it "treats as truncate/extend (same behaviour as EndOfFile)" do
      allow(filesystem).to receive(:read_content).and_return(StringIO.new(content))
      written = nil
      allow(filesystem).to receive(:write_content) do |_path, io|
        written = io.read
        '"etag"'
      end
      of  = make_open_file
      buf = [5].pack("Q<")  # truncate to 5 bytes
      result = described_class.handle(
        build_set_info_body(of.file_id_bytes, info_type: 1, info_class: 0x13, buffer: buf),
        open_file_table: open_file_table
      )
      expect(result[:status]).to eq(C::Status::SUCCESS)
      expect(written).to eq("Hello")
    end
  end

  describe ".handle — unsupported FileInformationClass" do
    it "returns STATUS_INVALID_INFO_CLASS for unknown class within FILE info type" do
      of  = make_open_file
      buf = "ignored".b
      result = described_class.handle(
        build_set_info_body(of.file_id_bytes, info_type: 1, info_class: 0xFF, buffer: buf),
        open_file_table: open_file_table
      )
      expect(result[:status]).to eq(C::Status::INVALID_INFO_CLASS)
    end
  end

  describe ".handle — non-FILE InfoType" do
    it "returns STATUS_INVALID_INFO_CLASS for filesystem info type" do
      of  = make_open_file
      buf = "ignored".b
      result = described_class.handle(
        build_set_info_body(of.file_id_bytes, info_type: 2, info_class: 0x01, buffer: buf),
        open_file_table: open_file_table
      )
      expect(result[:status]).to eq(C::Status::INVALID_INFO_CLASS)
    end
  end
end
