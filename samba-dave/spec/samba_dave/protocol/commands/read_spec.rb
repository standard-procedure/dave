# frozen_string_literal: true

require "spec_helper"
require "stringio"
require "dave/resource"
require "samba_dave/tree_connect"
require "samba_dave/open_file"
require "samba_dave/open_file_table"
require "samba_dave/protocol/commands/read"

RSpec.describe SambaDave::Protocol::Commands::Read do
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

  # Build a READ request body.
  # Fixed structure: StructureSize(2) Padding(1) Flags(1) Length(4) Offset(8)
  #                  FileId.Persistent(8) FileId.Volatile(8)
  #                  MinimumCount(4) Channel(4) RemainingBytes(4)
  #                  ReadChannelInfoOffset(2) ReadChannelInfoLength(2) Buffer(1)
  # Total: 49 bytes (StructureSize = 49)
  def build_read_body(file_id_bytes, length:, offset:, min_count: 0)
    persistent = file_id_bytes[0, 8].unpack1("Q<")
    volatile   = file_id_bytes[8, 8].unpack1("Q<")
    [49, 0, 0, length, offset, persistent, volatile,
     min_count, 0, 0, 0, 0, 0].pack("S<CCL<Q<Q<Q<L<L<L<S<S<C")
  end

  describe ".handle — invalid handle" do
    it "returns STATUS_INVALID_HANDLE for an unknown FileId" do
      unknown_id = open_file_table.generate_file_id
      result     = described_class.handle(build_read_body(unknown_id, length: 100, offset: 0),
                                          open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::INVALID_HANDLE)
    end
  end

  describe ".handle — reading a directory" do
    it "returns STATUS_INVALID_PARAMETER" do
      of     = make_open_file(is_directory: true, path: "/dir/")
      result = described_class.handle(build_read_body(of.file_id_bytes, length: 100, offset: 0),
                                      open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::INVALID_PARAMETER)
    end
  end

  describe ".handle — reading a file" do
    let(:content) { "Hello, World!" }

    before do
      allow(filesystem).to receive(:read_content).and_return(StringIO.new(content))
    end

    it "returns STATUS_SUCCESS" do
      of     = make_open_file
      result = described_class.handle(build_read_body(of.file_id_bytes, length: 100, offset: 0),
                                      open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "returns the file content in the response body" do
      of       = make_open_file
      result   = described_class.handle(build_read_body(of.file_id_bytes, length: 100, offset: 0),
                                        open_file_table: open_file_table)
      response = SambaDave::Protocol::Commands::ReadResponse.read(result[:body])
      expect(response.buffer).to eq(content)
    end

    it "returns the correct DataLength" do
      of       = make_open_file
      result   = described_class.handle(build_read_body(of.file_id_bytes, length: 100, offset: 0),
                                        open_file_table: open_file_table)
      response = SambaDave::Protocol::Commands::ReadResponse.read(result[:body])
      expect(response.data_length).to eq(content.bytesize)
    end

    it "returns StructureSize=17 in the response" do
      of       = make_open_file
      result   = described_class.handle(build_read_body(of.file_id_bytes, length: 100, offset: 0),
                                        open_file_table: open_file_table)
      response = SambaDave::Protocol::Commands::ReadResponse.read(result[:body])
      expect(response.structure_size).to eq(17)
    end

    it "returns DataOffset=80 (64 header + 16 fixed response)" do
      of       = make_open_file
      result   = described_class.handle(build_read_body(of.file_id_bytes, length: 100, offset: 0),
                                        open_file_table: open_file_table)
      response = SambaDave::Protocol::Commands::ReadResponse.read(result[:body])
      expect(response.data_offset).to eq(80)
    end

    context "with a non-zero offset" do
      it "reads data starting at the given offset" do
        allow(filesystem).to receive(:read_content).and_return(StringIO.new(content))
        of     = make_open_file
        result = described_class.handle(build_read_body(of.file_id_bytes, length: 5, offset: 7),
                                        open_file_table: open_file_table)
        response = SambaDave::Protocol::Commands::ReadResponse.read(result[:body])
        expect(response.buffer).to eq(content[7, 5])
      end
    end

    context "when offset >= file size" do
      it "returns STATUS_END_OF_FILE" do
        allow(filesystem).to receive(:read_content).and_return(StringIO.new(content))
        of     = make_open_file
        result = described_class.handle(
          build_read_body(of.file_id_bytes, length: 10, offset: content.bytesize + 100),
          open_file_table: open_file_table
        )
        expect(result[:status]).to eq(C::Status::END_OF_FILE)
      end
    end

    context "when requesting more bytes than available" do
      it "returns the available bytes with STATUS_SUCCESS" do
        allow(filesystem).to receive(:read_content).and_return(StringIO.new(content))
        of     = make_open_file
        # Request more than file contains
        result = described_class.handle(
          build_read_body(of.file_id_bytes, length: 1_000_000, offset: 0),
          open_file_table: open_file_table
        )
        expect(result[:status]).to eq(C::Status::SUCCESS)
        response = SambaDave::Protocol::Commands::ReadResponse.read(result[:body])
        expect(response.buffer).to eq(content)
      end
    end
  end

  describe ".handle — large file streaming" do
    it "reads a multi-megabyte file correctly in sequential chunks" do
      chunk_size = 1_048_576  # 1 MiB
      file_data  = ("A" * chunk_size) + ("B" * chunk_size) + ("C" * 512)
      total_size = file_data.bytesize

      of = make_open_file

      # First chunk: bytes 0..1MiB-1
      allow(filesystem).to receive(:read_content).and_return(StringIO.new(file_data))
      result1   = described_class.handle(
        build_read_body(of.file_id_bytes, length: chunk_size, offset: 0),
        open_file_table: open_file_table
      )
      expect(result1[:status]).to eq(C::Status::SUCCESS)
      r1 = SambaDave::Protocol::Commands::ReadResponse.read(result1[:body])
      expect(r1.data_length).to eq(chunk_size)
      expect(r1.buffer).to eq("A" * chunk_size)

      # Second chunk: bytes 1MiB..2MiB-1
      allow(filesystem).to receive(:read_content).and_return(StringIO.new(file_data))
      result2   = described_class.handle(
        build_read_body(of.file_id_bytes, length: chunk_size, offset: chunk_size),
        open_file_table: open_file_table
      )
      expect(result2[:status]).to eq(C::Status::SUCCESS)
      r2 = SambaDave::Protocol::Commands::ReadResponse.read(result2[:body])
      expect(r2.data_length).to eq(chunk_size)
      expect(r2.buffer).to eq("B" * chunk_size)

      # Third chunk: remainder
      allow(filesystem).to receive(:read_content).and_return(StringIO.new(file_data))
      result3   = described_class.handle(
        build_read_body(of.file_id_bytes, length: chunk_size, offset: chunk_size * 2),
        open_file_table: open_file_table
      )
      expect(result3[:status]).to eq(C::Status::SUCCESS)
      r3 = SambaDave::Protocol::Commands::ReadResponse.read(result3[:body])
      expect(r3.data_length).to eq(512)
      expect(r3.buffer).to eq("C" * 512)

      # Past end of file
      allow(filesystem).to receive(:read_content).and_return(StringIO.new(file_data))
      result4 = described_class.handle(
        build_read_body(of.file_id_bytes, length: chunk_size, offset: total_size),
        open_file_table: open_file_table
      )
      expect(result4[:status]).to eq(C::Status::END_OF_FILE)
    end
  end
end
