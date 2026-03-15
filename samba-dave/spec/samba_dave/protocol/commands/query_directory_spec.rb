# frozen_string_literal: true

require "spec_helper"
require "dave/resource"
require "samba_dave/tree_connect"
require "samba_dave/open_file"
require "samba_dave/open_file_table"
require "samba_dave/protocol/commands/query_directory"

RSpec.describe SambaDave::Protocol::Commands::QueryDirectory do
  C = SambaDave::Protocol::Constants

  # FileInformationClass for QUERY_DIRECTORY
  FILE_ID_BOTH_DIR_INFO  = 0x25
  FILE_BOTH_DIR_INFO     = 0x03
  FILE_ID_FULL_DIR_INFO  = 0x26  # Windows Explorer uses this

  # Flags
  FLAG_RESTART_SCANS   = 0x01
  FLAG_RETURN_SINGLE   = 0x02

  let(:now) { Time.at(1_700_000_000).utc }

  def make_resource(path, is_dir: false, size: 100)
    Dave::Resource.new(
      path: path, collection: is_dir,
      content_type: is_dir ? nil : "text/plain",
      content_length: is_dir ? nil : size,
      etag: '"e"', last_modified: now, created_at: now
    )
  end

  let(:root_resource)  { make_resource("/",        is_dir: true) }
  let(:file1_resource) { make_resource("/a.txt",   is_dir: false, size: 10) }
  let(:file2_resource) { make_resource("/b.txt",   is_dir: false, size: 20) }
  let(:subdir_resource){ make_resource("/sub/",    is_dir: true) }

  let(:children) { [file1_resource, file2_resource, subdir_resource] }

  let(:filesystem) do
    double("FileSystemProvider",
           get_resource: root_resource,
           list_children: children)
  end

  let(:tree_connect)    { SambaDave::TreeConnect.new(tree_id: 1, share_name: "s", filesystem: filesystem) }
  let(:open_file_table) { SambaDave::OpenFileTable.new }

  def make_dir_handle(path: "/", resource: root_resource)
    allow(filesystem).to receive(:get_resource).with(path).and_return(resource)
    fid = open_file_table.generate_file_id
    of  = SambaDave::OpenFile.new(
      file_id_bytes: fid,
      path:          path,
      is_directory:  true,
      tree_connect:  tree_connect
    )
    open_file_table.add(of)
    of
  end

  # Build QUERY_DIRECTORY request body (32 bytes fixed + pattern):
  #   StructureSize (2) = 33
  #   FileInformationClass (1)
  #   Flags (1)
  #   FileIndex (4)
  #   FileId.Persistent (8)
  #   FileId.Volatile (8)
  #   FileNameOffset (2)
  #   FileNameLength (2)
  #   OutputBufferLength (4)
  #   FileName (var, UTF-16LE)
  def build_query_dir_body(file_id_bytes:, pattern: "*", info_class: FILE_ID_BOTH_DIR_INFO,
                           flags: 0, output_buffer_length: 65535)
    persistent   = file_id_bytes[0, 8].unpack1("Q<")
    volatile     = file_id_bytes[8, 8].unpack1("Q<")
    pattern_bytes = pattern.encode("UTF-16LE").b
    name_offset  = 64 + 32  # header(64) + fixed body(32)
    [
      33, info_class, flags, 0,
      persistent, volatile,
      name_offset, pattern_bytes.bytesize,
      output_buffer_length
    ].pack("S<CCL<Q<Q<S<S<L<") + pattern_bytes
  end

  describe ".handle — first call lists entries including . and .." do
    it "returns STATUS_SUCCESS" do
      of     = make_dir_handle
      allow(filesystem).to receive(:list_children).and_return(children)
      result = described_class.handle(build_query_dir_body(file_id_bytes: of.file_id_bytes),
                                      open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "returns a non-empty buffer" do
      of = make_dir_handle
      allow(filesystem).to receive(:list_children).and_return(children)
      result = described_class.handle(build_query_dir_body(file_id_bytes: of.file_id_bytes),
                                      open_file_table: open_file_table)
      response = SambaDave::Protocol::Commands::QueryDirectoryResponse.read(result[:body])
      expect(response.output_buffer_length).to be > 0
    end

    it "includes the . (current dir) entry" do
      of = make_dir_handle
      allow(filesystem).to receive(:list_children).and_return(children)
      result  = described_class.handle(build_query_dir_body(file_id_bytes: of.file_id_bytes),
                                       open_file_table: open_file_table)
      entries = parse_dir_entries(result[:body])
      names   = entries.map { |e| e[:name] }
      expect(names).to include(".")
    end

    it "includes the .. (parent dir) entry" do
      of = make_dir_handle
      allow(filesystem).to receive(:list_children).and_return(children)
      result  = described_class.handle(build_query_dir_body(file_id_bytes: of.file_id_bytes),
                                       open_file_table: open_file_table)
      entries = parse_dir_entries(result[:body])
      names   = entries.map { |e| e[:name] }
      expect(names).to include("..")
    end

    it "includes all child entries" do
      of = make_dir_handle
      allow(filesystem).to receive(:list_children).and_return(children)
      result  = described_class.handle(build_query_dir_body(file_id_bytes: of.file_id_bytes),
                                       open_file_table: open_file_table)
      entries = parse_dir_entries(result[:body])
      names   = entries.map { |e| e[:name] }
      expect(names).to include("a.txt")
      expect(names).to include("b.txt")
      expect(names).to include("sub")
    end
  end

  describe ".handle — second call returns STATUS_NO_MORE_FILES" do
    it "returns NO_MORE_FILES on a subsequent call after all entries returned" do
      of = make_dir_handle
      allow(filesystem).to receive(:list_children).and_return(children)

      # First call — get all entries
      body = build_query_dir_body(file_id_bytes: of.file_id_bytes)
      described_class.handle(body, open_file_table: open_file_table)

      # Second call — should return NO_MORE_FILES
      result = described_class.handle(body, open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::NO_MORE_FILES)
    end
  end

  describe ".handle — RESTART_SCANS flag resets enumeration" do
    it "returns entries again after RESTART_SCANS" do
      of = make_dir_handle
      allow(filesystem).to receive(:list_children).and_return(children)

      body = build_query_dir_body(file_id_bytes: of.file_id_bytes)
      described_class.handle(body, open_file_table: open_file_table)

      # Restart
      restart_body = build_query_dir_body(file_id_bytes: of.file_id_bytes,
                                          flags: FLAG_RESTART_SCANS)
      result = described_class.handle(restart_body, open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end
  end

  describe ".handle — invalid FileId" do
    it "returns STATUS_INVALID_HANDLE" do
      unknown_id = open_file_table.generate_file_id
      result     = described_class.handle(
        build_query_dir_body(file_id_bytes: unknown_id),
        open_file_table: open_file_table
      )
      expect(result[:status]).to eq(C::Status::INVALID_HANDLE)
    end
  end

  describe ".handle — empty directory" do
    it "returns STATUS_NO_MORE_FILES on second call (after . and ..) with empty dir" do
      of = make_dir_handle
      allow(filesystem).to receive(:list_children).and_return([])

      body = build_query_dir_body(file_id_bytes: of.file_id_bytes)
      described_class.handle(body, open_file_table: open_file_table)
      result = described_class.handle(body, open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::NO_MORE_FILES)
    end
  end

  describe ".handle — FileIdBothDirectoryInformation entry format" do
    it "encodes FileName as UTF-16LE with correct FileNameLength" do
      of = make_dir_handle
      allow(filesystem).to receive(:list_children).and_return([file1_resource])

      result  = described_class.handle(build_query_dir_body(file_id_bytes: of.file_id_bytes),
                                       open_file_table: open_file_table)
      entries = parse_dir_entries(result[:body])
      a_entry = entries.find { |e| e[:name] == "a.txt" }
      expect(a_entry).not_to be_nil
      expect(a_entry[:name_length]).to eq("a.txt".bytesize * 2)  # UTF-16LE
    end
  end

  # ── Windows Explorer compatibility ────────────────────────────────────────

  describe ".handle — FileIdFullDirectoryInformation (0x26)" do
    it "returns STATUS_SUCCESS" do
      of = make_dir_handle
      allow(filesystem).to receive(:list_children).and_return(children)
      result = described_class.handle(
        build_query_dir_body(file_id_bytes: of.file_id_bytes, info_class: FILE_ID_FULL_DIR_INFO),
        open_file_table: open_file_table
      )
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "returns a non-empty buffer with file entries" do
      of = make_dir_handle
      allow(filesystem).to receive(:list_children).and_return(children)
      result = described_class.handle(
        build_query_dir_body(file_id_bytes: of.file_id_bytes, info_class: FILE_ID_FULL_DIR_INFO),
        open_file_table: open_file_table
      )
      resp = SambaDave::Protocol::Commands::QueryDirectoryResponse.read(result[:body])
      expect(resp.output_buffer_length).to be > 0
    end

    it "includes . and .. entries" do
      of = make_dir_handle
      allow(filesystem).to receive(:list_children).and_return([])
      result  = described_class.handle(
        build_query_dir_body(file_id_bytes: of.file_id_bytes, info_class: FILE_ID_FULL_DIR_INFO),
        open_file_table: open_file_table
      )
      entries = parse_full_dir_entries(result[:body])
      names   = entries.map { |e| e[:name] }
      expect(names).to include(".")
      expect(names).to include("..")
    end

    it "includes child file entries with correct names" do
      of = make_dir_handle
      allow(filesystem).to receive(:list_children).and_return([file1_resource])
      result  = described_class.handle(
        build_query_dir_body(file_id_bytes: of.file_id_bytes, info_class: FILE_ID_FULL_DIR_INFO),
        open_file_table: open_file_table
      )
      entries = parse_full_dir_entries(result[:body])
      names   = entries.map { |e| e[:name] }
      expect(names).to include("a.txt")
    end

    it "returns STATUS_NO_MORE_FILES on exhaustion" do
      of = make_dir_handle
      allow(filesystem).to receive(:list_children).and_return([])
      body = build_query_dir_body(file_id_bytes: of.file_id_bytes, info_class: FILE_ID_FULL_DIR_INFO)
      described_class.handle(body, open_file_table: open_file_table)
      result = described_class.handle(body, open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::NO_MORE_FILES)
    end
  end

  # ── Helper: parse FileIdBothDirectoryInformation entries from response buffer ─

  def parse_dir_entries(response_body)
    resp   = SambaDave::Protocol::Commands::QueryDirectoryResponse.read(response_body)
    buf    = resp.output_buffer
    offset = 0
    entries = []

    loop do
      break if offset >= buf.bytesize
      # Parse fixed portion (104 bytes for FileIdBothDirectoryInformation)
      fixed = buf[offset, 104]
      break if fixed.nil? || fixed.bytesize < 104

      next_offset, _file_index,
      _creation, _last_access, _last_write, _change,
      _end_of_file, _alloc_size,
      _attrs,
      name_length, _ea_size,
      _short_name_len, _reserved1,
      _short_name_bytes,
      _reserved2, _file_id = fixed.unpack("L<L<Q<Q<Q<Q<Q<Q<L<L<L<CCA24S<Q<")

      name_bytes = buf[offset + 104, name_length]
      name       = name_bytes.force_encoding("UTF-16LE").encode("UTF-8", invalid: :replace, undef: :replace)

      entries << { name: name, name_length: name_length }

      break if next_offset == 0
      offset += next_offset
    end

    entries
  end

  # Helper: parse FileIdFullDirectoryInformation entries from response buffer.
  # Fixed portion = 80 bytes (no short name fields).
  # NextEntryOffset(4) FileIndex(4) CreationTime(8) LastAccessTime(8)
  # LastWriteTime(8) ChangeTime(8) EndOfFile(8) AllocationSize(8)
  # FileAttributes(4) FileNameLength(4) EaSize(4) Reserved(4) FileId(8)
  # FileName(FileNameLength)
  def parse_full_dir_entries(response_body)
    resp   = SambaDave::Protocol::Commands::QueryDirectoryResponse.read(response_body)
    buf    = resp.output_buffer
    offset = 0
    entries = []

    loop do
      break if offset >= buf.bytesize
      fixed = buf[offset, 80]
      break if fixed.nil? || fixed.bytesize < 80

      next_offset, _file_index,
      _creation, _last_access, _last_write, _change,
      _end_of_file, _alloc_size,
      _attrs, name_length = fixed.unpack("L<L<Q<Q<Q<Q<Q<Q<L<L<")

      name_bytes = buf[offset + 80, name_length]
      name       = name_bytes.force_encoding("UTF-16LE").encode("UTF-8", invalid: :replace, undef: :replace)
      entries << { name: name, name_length: name_length }

      break if next_offset == 0
      offset += next_offset
    end

    entries
  end
end
