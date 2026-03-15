# frozen_string_literal: true

require "spec_helper"
require "dave/resource"
require "samba_dave/tree_connect"
require "samba_dave/open_file"
require "samba_dave/open_file_table"
require "samba_dave/protocol/commands/query_info"

RSpec.describe SambaDave::Protocol::Commands::QueryInfo do
  C = SambaDave::Protocol::Constants

  # InfoType values
  INFO_TYPE_FILE       = 0x01
  INFO_TYPE_FILESYSTEM = 0x02

  # FileInformationClass values
  FILE_BASIC_INFO          = 0x04
  FILE_STANDARD_INFO       = 0x05
  FILE_NETWORK_OPEN_INFO   = 0x22

  # FsInformationClass values
  FS_VOLUME_INFO = 0x01
  FS_SIZE_INFO   = 0x03

  let(:now)  { Time.at(1_700_000_000).utc }  # fixed time for testing
  let(:file_resource) do
    Dave::Resource.new(
      path: "/report.txt", collection: false,
      content_type: "text/plain", content_length: 1234,
      etag: '"abc"', last_modified: now, created_at: now
    )
  end
  let(:dir_resource) do
    Dave::Resource.new(
      path: "/docs/", collection: true,
      content_type: nil, content_length: nil,
      etag: '"dir"', last_modified: now, created_at: now
    )
  end
  let(:filesystem)      { double("FileSystemProvider", get_resource: file_resource) }
  let(:tree_connect)    { SambaDave::TreeConnect.new(tree_id: 1, share_name: "s", filesystem: filesystem) }
  let(:open_file_table) { SambaDave::OpenFileTable.new }

  def make_open_file(resource, is_directory: false)
    fid = open_file_table.generate_file_id
    of  = SambaDave::OpenFile.new(
      file_id_bytes: fid,
      path:          resource.path,
      is_directory:  is_directory,
      tree_connect:  tree_connect
    )
    open_file_table.add(of)
    of
  end

  # Build QUERY_INFO request body (40 bytes fixed + optional input buffer):
  #   StructureSize (2) = 41
  #   InfoType (1)
  #   FileInformationClass (1)
  #   OutputBufferLength (4)
  #   InputBufferOffset (2)
  #   Reserved (2)
  #   InputBufferLength (4)
  #   AdditionalInformation (4)
  #   Flags (4)
  #   FileId.Persistent (8)
  #   FileId.Volatile (8)
  #   Total fixed: 2+1+1+4+2+2+4+4+4+8+8 = 40 bytes
  def build_query_info_body(file_id_bytes:, info_type:, info_class:, output_buffer_length: 4096)
    persistent = file_id_bytes[0, 8].unpack1("Q<")
    volatile   = file_id_bytes[8, 8].unpack1("Q<")
    [
      41, info_type, info_class, output_buffer_length,
      0, 0, 0, 0, 0,
      persistent, volatile
    ].pack("S<CCL<S<S<L<L<L<Q<Q<")
  end

  # FILETIME epoch difference (100-ns intervals 1601-01-01 to 1970-01-01)
  EPOCH_DIFF = 116_444_736_000_000_000

  def ruby_time_to_filetime(t)
    (t.to_i * 10_000_000) + (t.nsec / 100) + EPOCH_DIFF
  end

  describe ".handle — FileBasicInformation (0x04)" do
    it "returns STATUS_SUCCESS" do
      of     = make_open_file(file_resource)
      allow(filesystem).to receive(:get_resource).with("/report.txt").and_return(file_resource)
      result = described_class.handle(
        build_query_info_body(file_id_bytes: of.file_id_bytes,
                              info_type: INFO_TYPE_FILE, info_class: FILE_BASIC_INFO),
        open_file_table: open_file_table
      )
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "returns a 40-byte info buffer (4 × FILETIME + FileAttributes + Reserved)" do
      of = make_open_file(file_resource)
      allow(filesystem).to receive(:get_resource).and_return(file_resource)
      result = described_class.handle(
        build_query_info_body(file_id_bytes: of.file_id_bytes,
                              info_type: INFO_TYPE_FILE, info_class: FILE_BASIC_INFO),
        open_file_table: open_file_table
      )
      # Response body: StructureSize(2) + Offset(2) + Length(4) + Buffer
      resp_body = SambaDave::Protocol::Commands::QueryInfoResponse.read(result[:body])
      expect(resp_body.output_buffer_length).to eq(40)
    end

    it "encodes last_modified as the LastWriteTime FILETIME" do
      of = make_open_file(file_resource)
      allow(filesystem).to receive(:get_resource).and_return(file_resource)
      result   = described_class.handle(
        build_query_info_body(file_id_bytes: of.file_id_bytes,
                              info_type: INFO_TYPE_FILE, info_class: FILE_BASIC_INFO),
        open_file_table: open_file_table
      )
      resp      = SambaDave::Protocol::Commands::QueryInfoResponse.read(result[:body])
      buf       = resp.output_buffer
      # FileBasicInformation layout: CreationTime(8), LastAccessTime(8), LastWriteTime(8), ChangeTime(8), FileAttributes(4), Reserved(4)
      write_time = buf[16, 8].unpack1("Q<")
      expect(write_time).to eq(ruby_time_to_filetime(now))
    end
  end

  describe ".handle — FileStandardInformation (0x05)" do
    it "returns STATUS_SUCCESS" do
      of = make_open_file(file_resource)
      allow(filesystem).to receive(:get_resource).and_return(file_resource)
      result = described_class.handle(
        build_query_info_body(file_id_bytes: of.file_id_bytes,
                              info_type: INFO_TYPE_FILE, info_class: FILE_STANDARD_INFO),
        open_file_table: open_file_table
      )
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "returns a 24-byte info buffer" do
      of = make_open_file(file_resource)
      allow(filesystem).to receive(:get_resource).and_return(file_resource)
      result = described_class.handle(
        build_query_info_body(file_id_bytes: of.file_id_bytes,
                              info_type: INFO_TYPE_FILE, info_class: FILE_STANDARD_INFO),
        open_file_table: open_file_table
      )
      resp = SambaDave::Protocol::Commands::QueryInfoResponse.read(result[:body])
      expect(resp.output_buffer_length).to eq(24)
    end

    it "returns the correct EndOfFile from content_length" do
      of = make_open_file(file_resource)
      allow(filesystem).to receive(:get_resource).and_return(file_resource)
      result = described_class.handle(
        build_query_info_body(file_id_bytes: of.file_id_bytes,
                              info_type: INFO_TYPE_FILE, info_class: FILE_STANDARD_INFO),
        open_file_table: open_file_table
      )
      resp       = SambaDave::Protocol::Commands::QueryInfoResponse.read(result[:body])
      buf        = resp.output_buffer
      # FileStandardInformation: AllocationSize(8), EndOfFile(8), NumberOfLinks(4), DeletePending(1), Directory(1), Reserved(2)
      end_of_file = buf[8, 8].unpack1("Q<")
      expect(end_of_file).to eq(1234)
    end

    it "sets Directory=1 for directory handles" do
      of = make_open_file(dir_resource, is_directory: true)
      allow(filesystem).to receive(:get_resource).and_return(dir_resource)
      result = described_class.handle(
        build_query_info_body(file_id_bytes: of.file_id_bytes,
                              info_type: INFO_TYPE_FILE, info_class: FILE_STANDARD_INFO),
        open_file_table: open_file_table
      )
      resp      = SambaDave::Protocol::Commands::QueryInfoResponse.read(result[:body])
      buf       = resp.output_buffer
      # FileStandardInformation layout: AllocationSize(8) EndOfFile(8) NumberOfLinks(4) DeletePending(1) Directory(1)
      directory = buf[21, 1].unpack1("C")
      expect(directory).to eq(1)
    end
  end

  describe ".handle — FileNetworkOpenInformation (0x22)" do
    it "returns STATUS_SUCCESS" do
      of = make_open_file(file_resource)
      allow(filesystem).to receive(:get_resource).and_return(file_resource)
      result = described_class.handle(
        build_query_info_body(file_id_bytes: of.file_id_bytes,
                              info_type: INFO_TYPE_FILE, info_class: FILE_NETWORK_OPEN_INFO),
        open_file_table: open_file_table
      )
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "returns a 56-byte info buffer" do
      of = make_open_file(file_resource)
      allow(filesystem).to receive(:get_resource).and_return(file_resource)
      result = described_class.handle(
        build_query_info_body(file_id_bytes: of.file_id_bytes,
                              info_type: INFO_TYPE_FILE, info_class: FILE_NETWORK_OPEN_INFO),
        open_file_table: open_file_table
      )
      resp = SambaDave::Protocol::Commands::QueryInfoResponse.read(result[:body])
      expect(resp.output_buffer_length).to eq(56)
    end
  end

  describe ".handle — unknown FileInformationClass" do
    it "returns STATUS_INVALID_INFO_CLASS" do
      of = make_open_file(file_resource)
      result = described_class.handle(
        build_query_info_body(file_id_bytes: of.file_id_bytes,
                              info_type: INFO_TYPE_FILE, info_class: 0xFF),
        open_file_table: open_file_table
      )
      expect(result[:status]).to eq(C::Status::INVALID_INFO_CLASS)
    end
  end

  describe ".handle — FileFsVolumeInformation (0x01)" do
    it "returns STATUS_SUCCESS" do
      of = make_open_file(file_resource)
      result = described_class.handle(
        build_query_info_body(file_id_bytes: of.file_id_bytes,
                              info_type: INFO_TYPE_FILESYSTEM, info_class: FS_VOLUME_INFO),
        open_file_table: open_file_table
      )
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "returns a non-empty buffer with VolumeCreationTime and SerialNumber" do
      of = make_open_file(file_resource)
      result = described_class.handle(
        build_query_info_body(file_id_bytes: of.file_id_bytes,
                              info_type: INFO_TYPE_FILESYSTEM, info_class: FS_VOLUME_INFO),
        open_file_table: open_file_table
      )
      resp = SambaDave::Protocol::Commands::QueryInfoResponse.read(result[:body])
      expect(resp.output_buffer_length).to be > 0
    end
  end

  describe ".handle — FileFsSizeInformation (0x03)" do
    it "returns STATUS_SUCCESS" do
      of = make_open_file(file_resource)
      result = described_class.handle(
        build_query_info_body(file_id_bytes: of.file_id_bytes,
                              info_type: INFO_TYPE_FILESYSTEM, info_class: FS_SIZE_INFO),
        open_file_table: open_file_table
      )
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "returns a 24-byte buffer (TotalAllocationUnits, AvailableAllocationUnits, SectorsPerUnit, BytesPerSector)" do
      of = make_open_file(file_resource)
      result = described_class.handle(
        build_query_info_body(file_id_bytes: of.file_id_bytes,
                              info_type: INFO_TYPE_FILESYSTEM, info_class: FS_SIZE_INFO),
        open_file_table: open_file_table
      )
      resp = SambaDave::Protocol::Commands::QueryInfoResponse.read(result[:body])
      expect(resp.output_buffer_length).to eq(24)
    end
  end

  describe ".handle — invalid FileId" do
    it "returns STATUS_INVALID_HANDLE" do
      unknown_id = open_file_table.generate_file_id
      result     = described_class.handle(
        build_query_info_body(file_id_bytes: unknown_id,
                              info_type: INFO_TYPE_FILE, info_class: FILE_BASIC_INFO),
        open_file_table: open_file_table
      )
      expect(result[:status]).to eq(C::Status::INVALID_HANDLE)
    end
  end
end
