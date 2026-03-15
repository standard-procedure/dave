# frozen_string_literal: true

require "spec_helper"
require "stringio"
require "dave/resource"
require "samba_dave/tree_connect"
require "samba_dave/open_file"
require "samba_dave/open_file_table"
require "samba_dave/protocol/commands/write"

RSpec.describe SambaDave::Protocol::Commands::Write do
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

  # Build a WRITE request body.
  # Fixed structure (48 bytes):
  #   StructureSize(2) DataOffset(2) Length(4) Offset(8)
  #   FileId.Persistent(8) FileId.Volatile(8)
  #   Channel(4) RemainingBytes(4) WriteChannelInfoOffset(2) WriteChannelInfoLength(2) Flags(4)
  # Followed by the data buffer.
  #
  # DataOffset = 64 (SMB2 header) + 48 (fixed request body) = 112
  # Body is everything AFTER the 64-byte header, so data starts at offset 48 within body.
  def build_write_body(file_id_bytes, data, file_offset:)
    persistent  = file_id_bytes[0, 8].unpack1("Q<")
    volatile    = file_id_bytes[8, 8].unpack1("Q<")
    data_offset = 112  # 64 header + 48 fixed body
    fixed = [49, data_offset, data.bytesize, file_offset,
             persistent, volatile, 0, 0, 0, 0, 0].pack("S<S<L<Q<Q<Q<L<L<S<S<L<")
    fixed + data.b
  end

  describe ".handle — invalid handle" do
    it "returns STATUS_INVALID_HANDLE for an unknown FileId" do
      unknown_id = open_file_table.generate_file_id
      result     = described_class.handle(build_write_body(unknown_id, "hello", file_offset: 0),
                                          open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::INVALID_HANDLE)
    end
  end

  describe ".handle — writing to a directory" do
    it "returns STATUS_INVALID_PARAMETER" do
      of     = make_open_file(is_directory: true, path: "/dir/")
      result = described_class.handle(build_write_body(of.file_id_bytes, "hello", file_offset: 0),
                                      open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::INVALID_PARAMETER)
    end
  end

  describe ".handle — writing to a file" do
    let(:initial_content) { "Hello, World!" }

    before do
      allow(filesystem).to receive(:read_content).and_return(StringIO.new(initial_content))
      allow(filesystem).to receive(:write_content)
    end

    it "returns STATUS_SUCCESS" do
      of     = make_open_file
      result = described_class.handle(build_write_body(of.file_id_bytes, "X", file_offset: 0),
                                      open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "returns the byte count written in the response" do
      data   = "New content"
      of     = make_open_file
      result = described_class.handle(build_write_body(of.file_id_bytes, data, file_offset: 0),
                                      open_file_table: open_file_table)
      response = SambaDave::Protocol::Commands::WriteResponse.read(result[:body])
      expect(response.bytes_written).to eq(data.bytesize)
    end

    it "returns StructureSize=17 in the response" do
      of       = make_open_file
      result   = described_class.handle(build_write_body(of.file_id_bytes, "X", file_offset: 0),
                                        open_file_table: open_file_table)
      response = SambaDave::Protocol::Commands::WriteResponse.read(result[:body])
      expect(response.structure_size).to eq(17)
    end

    it "calls write_content with the new data at offset 0" do
      data = "Replacement"
      of   = make_open_file

      written_content = nil
      allow(filesystem).to receive(:write_content) do |_path, io|
        written_content = io.read
        '"etag"'
      end

      described_class.handle(build_write_body(of.file_id_bytes, data, file_offset: 0),
                             open_file_table: open_file_table)

      # Writes at offset 0 should splice the new data into the existing content
      expect(written_content).to start_with(data)
    end

    context "writing at a non-zero offset" do
      it "splices data into the correct position" do
        of   = make_open_file
        data = "XYZ"

        written_content = nil
        allow(filesystem).to receive(:write_content) do |_path, io|
          written_content = io.read
          '"etag"'
        end

        described_class.handle(build_write_body(of.file_id_bytes, data, file_offset: 7),
                               open_file_table: open_file_table)

        # "Hello, World!" with "XYZ" at offset 7 → "Hello, XYZld!"
        expect(written_content[7, 3]).to eq("XYZ")
        expect(written_content[0, 7]).to eq(initial_content[0, 7])
      end
    end

    context "writing beyond the current end of file" do
      it "extends the file with zeros and writes the data" do
        of   = make_open_file
        data = "END"

        written_content = nil
        allow(filesystem).to receive(:write_content) do |_path, io|
          written_content = io.read
          '"etag"'
        end

        # Write "END" starting 5 bytes past end of "Hello, World!"
        beyond_offset = initial_content.bytesize + 5
        described_class.handle(build_write_body(of.file_id_bytes, data, file_offset: beyond_offset),
                               open_file_table: open_file_table)

        # Content should be original + 5 zero bytes + "END"
        expect(written_content.bytesize).to eq(beyond_offset + data.bytesize)
        expect(written_content[0, initial_content.bytesize]).to eq(initial_content)
        expect(written_content[initial_content.bytesize, 5]).to eq("\x00" * 5)
        expect(written_content[beyond_offset, data.bytesize]).to eq(data)
      end
    end
  end

  describe ".handle — large file streaming" do
    it "writes a multi-megabyte file correctly in sequential chunks" do
      chunk_size = 1_048_576  # 1 MiB
      of         = make_open_file

      written_chunks = []

      # First write: offset=0
      allow(filesystem).to receive(:read_content).and_return(StringIO.new(""))
      allow(filesystem).to receive(:write_content) do |_path, io|
        written_chunks << [0, io.read]
        '"etag"'
      end
      result1 = described_class.handle(
        build_write_body(of.file_id_bytes, "A" * chunk_size, file_offset: 0),
        open_file_table: open_file_table
      )
      expect(result1[:status]).to eq(C::Status::SUCCESS)
      r1 = SambaDave::Protocol::Commands::WriteResponse.read(result1[:body])
      expect(r1.bytes_written).to eq(chunk_size)

      # Second write: offset=1MiB (simulate the file now contains the first chunk)
      allow(filesystem).to receive(:read_content).and_return(StringIO.new("A" * chunk_size))
      allow(filesystem).to receive(:write_content) do |_path, io|
        written_chunks << [chunk_size, io.read]
        '"etag"'
      end
      result2 = described_class.handle(
        build_write_body(of.file_id_bytes, "B" * chunk_size, file_offset: chunk_size),
        open_file_table: open_file_table
      )
      expect(result2[:status]).to eq(C::Status::SUCCESS)
      r2 = SambaDave::Protocol::Commands::WriteResponse.read(result2[:body])
      expect(r2.bytes_written).to eq(chunk_size)

      # Verify second write produced correct spliced content
      final_content = written_chunks.last[1]
      expect(final_content[0, chunk_size]).to eq("A" * chunk_size)
      expect(final_content[chunk_size, chunk_size]).to eq("B" * chunk_size)
    end
  end
end
