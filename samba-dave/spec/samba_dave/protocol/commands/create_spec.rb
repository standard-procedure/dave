# frozen_string_literal: true

require "spec_helper"
require "dave/resource"
require "samba_dave/tree_connect"
require "samba_dave/open_file"
require "samba_dave/open_file_table"
require "samba_dave/protocol/commands/create"

RSpec.describe SambaDave::Protocol::Commands::Create do
  C = SambaDave::Protocol::Constants

  # CreateDisposition values
  CREATE_DISPOSITION_SUPERSEDE     = 0
  CREATE_DISPOSITION_OPEN          = 1
  CREATE_DISPOSITION_CREATE        = 2
  CREATE_DISPOSITION_OPEN_IF       = 3
  CREATE_DISPOSITION_OVERWRITE     = 4
  CREATE_DISPOSITION_OVERWRITE_IF  = 5

  # CreateOptions flags
  FILE_DIRECTORY_FILE     = 0x00000001
  FILE_NON_DIRECTORY_FILE = 0x00000040

  let(:open_file_table) { SambaDave::OpenFileTable.new }

  # Build a raw CREATE request body. Name is UTF-16LE, relative to share root.
  # name_utf16: already-encoded UTF-16LE binary string (or nil for root)
  def build_create_body(name:, create_disposition:, create_options: 0, file_attributes: 0, desired_access: 0x001F01FF)
    name_bytes  = name.nil? ? "".b : name.encode("UTF-16LE").b
    name_offset = 64 + 56  # SMB2 header (64) + fixed CREATE body (56 bytes)
    name_length = name_bytes.bytesize

    [
      57,                 # StructureSize
      0,                  # SecurityFlags
      0,                  # RequestedOplockLevel (NONE)
      0,                  # ImpersonationLevel
      0,                  # SmbCreateFlags (8 bytes → split into two uint32)
      0,
      0,                  # Reserved (8 bytes → two uint32)
      0,
      desired_access,     # DesiredAccess
      file_attributes,    # FileAttributes
      0,                  # ShareAccess
      create_disposition, # CreateDisposition
      create_options,     # CreateOptions
      name_offset,        # NameOffset
      name_length,        # NameLength
      0,                  # CreateContextsOffset
      0,                  # CreateContextsLength
    ].pack("S<CCL<L<L<L<L<L<L<L<L<L<S<S<L<L<") + name_bytes
  end

  context "when the file exists" do
    let(:resource) do
      Dave::Resource.new(
        path: "/report.txt", collection: false,
        content_type: "text/plain", content_length: 42,
        etag: '"abc"', last_modified: Time.now, created_at: Time.now
      )
    end
    let(:filesystem) do
      double("FileSystemProvider", get_resource: resource)
    end
    let(:tree_connect) do
      SambaDave::TreeConnect.new(tree_id: 1, share_name: "share", filesystem: filesystem)
    end

    describe "OPEN disposition" do
      it "returns STATUS_SUCCESS" do
        body   = build_create_body(name: "report.txt", create_disposition: CREATE_DISPOSITION_OPEN)
        result = described_class.handle(body, tree_connect: tree_connect, open_file_table: open_file_table)
        expect(result[:status]).to eq(C::Status::SUCCESS)
      end

      it "returns a response body with StructureSize=89" do
        body     = build_create_body(name: "report.txt", create_disposition: CREATE_DISPOSITION_OPEN)
        result   = described_class.handle(body, tree_connect: tree_connect, open_file_table: open_file_table)
        response = SambaDave::Protocol::Commands::CreateResponse.read(result[:body])
        expect(response.structure_size).to eq(89)
      end

      it "returns CreateAction=FILE_OPENED (1)" do
        body     = build_create_body(name: "report.txt", create_disposition: CREATE_DISPOSITION_OPEN)
        result   = described_class.handle(body, tree_connect: tree_connect, open_file_table: open_file_table)
        response = SambaDave::Protocol::Commands::CreateResponse.read(result[:body])
        expect(response.create_action).to eq(1)  # FILE_OPENED
      end

      it "adds the file to the open_file_table" do
        body = build_create_body(name: "report.txt", create_disposition: CREATE_DISPOSITION_OPEN)
        described_class.handle(body, tree_connect: tree_connect, open_file_table: open_file_table)
        expect(open_file_table.size).to eq(1)
      end

      it "returns a non-zero FileId in the response" do
        body     = build_create_body(name: "report.txt", create_disposition: CREATE_DISPOSITION_OPEN)
        result   = described_class.handle(body, tree_connect: tree_connect, open_file_table: open_file_table)
        response = SambaDave::Protocol::Commands::CreateResponse.read(result[:body])
        file_id  = response.file_id_persistent.to_s + response.file_id_volatile.to_s
        expect(file_id).not_to eq("\x00" * 16)
      end

      it "returns EndOfFile from the resource content_length" do
        body     = build_create_body(name: "report.txt", create_disposition: CREATE_DISPOSITION_OPEN)
        result   = described_class.handle(body, tree_connect: tree_connect, open_file_table: open_file_table)
        response = SambaDave::Protocol::Commands::CreateResponse.read(result[:body])
        expect(response.end_of_file).to eq(42)
      end
    end

    describe "OPEN_IF disposition (file exists)" do
      it "returns STATUS_SUCCESS and FILE_OPENED" do
        body     = build_create_body(name: "report.txt", create_disposition: CREATE_DISPOSITION_OPEN_IF)
        result   = described_class.handle(body, tree_connect: tree_connect, open_file_table: open_file_table)
        response = SambaDave::Protocol::Commands::CreateResponse.read(result[:body])
        expect(result[:status]).to eq(C::Status::SUCCESS)
        expect(response.create_action).to eq(1)  # FILE_OPENED
      end
    end

    describe "CREATE disposition (file exists)" do
      it "returns STATUS_OBJECT_NAME_COLLISION" do
        body   = build_create_body(name: "report.txt", create_disposition: CREATE_DISPOSITION_CREATE)
        result = described_class.handle(body, tree_connect: tree_connect, open_file_table: open_file_table)
        expect(result[:status]).to eq(C::Status::OBJECT_NAME_COLLISION)
      end
    end

    describe "OVERWRITE disposition (file exists)" do
      let(:writable_fs) do
        double("FileSystemProvider",
               get_resource: resource,
               write_content: '"new_etag"')
      end
      let(:tc) do
        SambaDave::TreeConnect.new(tree_id: 1, share_name: "share", filesystem: writable_fs)
      end

      it "returns STATUS_SUCCESS and FILE_OVERWRITTEN (3)" do
        body     = build_create_body(name: "report.txt", create_disposition: CREATE_DISPOSITION_OVERWRITE)
        result   = described_class.handle(body, tree_connect: tc, open_file_table: open_file_table)
        response = SambaDave::Protocol::Commands::CreateResponse.read(result[:body])
        expect(result[:status]).to eq(C::Status::SUCCESS)
        expect(response.create_action).to eq(3)  # FILE_OVERWRITTEN
      end
    end

    describe "FILE_DIRECTORY_FILE create option on a file" do
      it "returns STATUS_NOT_A_DIRECTORY" do
        body   = build_create_body(name: "report.txt", create_disposition: CREATE_DISPOSITION_OPEN,
                                   create_options: FILE_DIRECTORY_FILE)
        result = described_class.handle(body, tree_connect: tree_connect, open_file_table: open_file_table)
        expect(result[:status]).to eq(C::Status::NOT_A_DIRECTORY)
      end
    end
  end

  context "when the path does not exist" do
    let(:filesystem) do
      double("FileSystemProvider", get_resource: nil)
    end
    let(:tree_connect) do
      SambaDave::TreeConnect.new(tree_id: 1, share_name: "share", filesystem: filesystem)
    end

    describe "OPEN disposition (not found)" do
      it "returns STATUS_OBJECT_NAME_NOT_FOUND" do
        body   = build_create_body(name: "missing.txt", create_disposition: CREATE_DISPOSITION_OPEN)
        result = described_class.handle(body, tree_connect: tree_connect, open_file_table: open_file_table)
        expect(result[:status]).to eq(C::Status::OBJECT_NAME_NOT_FOUND)
      end
    end

    describe "CREATE disposition (create new file)" do
      let(:new_resource) do
        Dave::Resource.new(
          path: "/newfile.txt", collection: false,
          content_type: "application/octet-stream", content_length: 0,
          etag: '"new"', last_modified: Time.now, created_at: Time.now
        )
      end
      let(:create_fs) do
        double("FileSystemProvider",
               get_resource: nil,
               write_content: '"new"')
      end
      let(:tc) do
        SambaDave::TreeConnect.new(tree_id: 1, share_name: "share", filesystem: create_fs)
      end

      it "returns STATUS_SUCCESS and FILE_CREATED (2)" do
        allow(create_fs).to receive(:get_resource).and_return(nil, new_resource)
        body     = build_create_body(name: "newfile.txt", create_disposition: CREATE_DISPOSITION_CREATE)
        result   = described_class.handle(body, tree_connect: tc, open_file_table: open_file_table)
        response = SambaDave::Protocol::Commands::CreateResponse.read(result[:body])
        expect(result[:status]).to eq(C::Status::SUCCESS)
        expect(response.create_action).to eq(2)  # FILE_CREATED
      end
    end

    describe "OPEN_IF disposition (create new)" do
      let(:new_resource) do
        Dave::Resource.new(
          path: "/new.txt", collection: false,
          content_type: "application/octet-stream", content_length: 0,
          etag: '"new"', last_modified: Time.now, created_at: Time.now
        )
      end
      let(:create_fs) do
        double("FileSystemProvider",
               get_resource: nil,
               write_content: '"new"')
      end
      let(:tc) do
        SambaDave::TreeConnect.new(tree_id: 1, share_name: "share", filesystem: create_fs)
      end

      it "returns STATUS_SUCCESS and FILE_CREATED (2)" do
        allow(create_fs).to receive(:get_resource).and_return(nil, new_resource)
        body     = build_create_body(name: "new.txt", create_disposition: CREATE_DISPOSITION_OPEN_IF)
        result   = described_class.handle(body, tree_connect: tc, open_file_table: open_file_table)
        response = SambaDave::Protocol::Commands::CreateResponse.read(result[:body])
        expect(result[:status]).to eq(C::Status::SUCCESS)
        expect(response.create_action).to eq(2)  # FILE_CREATED
      end
    end

    describe "OVERWRITE disposition (not found)" do
      it "returns STATUS_OBJECT_NAME_NOT_FOUND" do
        body   = build_create_body(name: "ghost.txt", create_disposition: CREATE_DISPOSITION_OVERWRITE)
        result = described_class.handle(body, tree_connect: tree_connect, open_file_table: open_file_table)
        expect(result[:status]).to eq(C::Status::OBJECT_NAME_NOT_FOUND)
      end
    end
  end

  context "when the path is a directory" do
    let(:dir_resource) do
      Dave::Resource.new(
        path: "/docs/", collection: true,
        content_type: nil, content_length: nil,
        etag: '"dir"', last_modified: Time.now, created_at: Time.now
      )
    end
    let(:filesystem) do
      double("FileSystemProvider", get_resource: dir_resource)
    end
    let(:tree_connect) do
      SambaDave::TreeConnect.new(tree_id: 1, share_name: "share", filesystem: filesystem)
    end

    it "opens a directory with FILE_DIRECTORY_FILE option" do
      body     = build_create_body(name: "docs", create_disposition: CREATE_DISPOSITION_OPEN,
                                   create_options: FILE_DIRECTORY_FILE)
      result   = described_class.handle(body, tree_connect: tree_connect, open_file_table: open_file_table)
      response = SambaDave::Protocol::Commands::CreateResponse.read(result[:body])
      expect(result[:status]).to eq(C::Status::SUCCESS)
      expect(response.file_attributes & C::FileAttributes::DIRECTORY).to eq(C::FileAttributes::DIRECTORY)
    end

    it "opens a directory without FILE_DIRECTORY_FILE (just browsing)" do
      body   = build_create_body(name: "docs", create_disposition: CREATE_DISPOSITION_OPEN)
      result = described_class.handle(body, tree_connect: tree_connect, open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "returns STATUS_FILE_IS_A_DIRECTORY with FILE_NON_DIRECTORY_FILE option" do
      body   = build_create_body(name: "docs", create_disposition: CREATE_DISPOSITION_OPEN,
                                  create_options: FILE_NON_DIRECTORY_FILE)
      result = described_class.handle(body, tree_connect: tree_connect, open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::FILE_IS_A_DIRECTORY)
    end
  end

  context "opening the root directory" do
    let(:root_resource) do
      Dave::Resource.new(
        path: "/", collection: true,
        content_type: nil, content_length: nil,
        etag: '"root"', last_modified: Time.now, created_at: Time.now
      )
    end
    let(:filesystem) do
      double("FileSystemProvider", get_resource: root_resource)
    end
    let(:tree_connect) do
      SambaDave::TreeConnect.new(tree_id: 1, share_name: "share", filesystem: filesystem)
    end

    it "opens root with empty name" do
      body   = build_create_body(name: "", create_disposition: CREATE_DISPOSITION_OPEN,
                                  create_options: FILE_DIRECTORY_FILE)
      result = described_class.handle(body, tree_connect: tree_connect, open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "opens root with backslash name" do
      body   = build_create_body(name: "\\", create_disposition: CREATE_DISPOSITION_OPEN,
                                  create_options: FILE_DIRECTORY_FILE)
      result = described_class.handle(body, tree_connect: tree_connect, open_file_table: open_file_table)
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end
  end
end
