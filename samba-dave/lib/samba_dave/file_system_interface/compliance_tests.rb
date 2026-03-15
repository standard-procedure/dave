# frozen_string_literal: true

module SambaDave
  module FileSystemInterface
    # Shared RSpec examples that verify a FileSystemInterface provider
    # correctly implements the operations required by samba-dave (SMB2 server).
    #
    # Usage in a spec file:
    #
    #   RSpec.describe MyProvider do
    #     subject { MyProvider.new(...) }
    #     include SambaDave::FileSystemInterface::ComplianceTests
    #   end
    #
    # The subject must be a configured provider instance that:
    # - starts with an empty root collection ("/")
    # - can be written to (no read-only restriction for tests)
    #
    module ComplianceTests
      def self.included(base)
        base.describe "SMB FileSystem Provider compliance (SambaDave)" do
          # subject must be set to a configured provider instance in the including spec

          # ── CREATE/OPEN equivalent ────────────────────────────────────────────

          it "returns nil for a non-existent path (CREATE open-existing would fail)" do
            expect(subject.get_resource("/nonexistent.txt")).to be_nil
          end

          it "creates a file and retrieves its metadata (CREATE + QUERY_INFO)" do
            subject.write_content("/smb-test.txt", StringIO.new("hello SMB"))
            resource = subject.get_resource("/smb-test.txt")
            expect(resource).not_to be_nil
            expect(resource.collection?).to be false
            expect(resource.content_length).to eq(9)
          end

          it "creates a directory (CREATE with DIRECTORY_FILE option)" do
            subject.create_collection("/smb-dir/")
            resource = subject.get_resource("/smb-dir/")
            expect(resource).not_to be_nil
            expect(resource.collection?).to be true
          end

          # ── READ ──────────────────────────────────────────────────────────────

          it "reads file content (READ command)" do
            subject.write_content("/read-test.txt", StringIO.new("read me"))
            io = subject.read_content("/read-test.txt")
            expect(io).to respond_to(:read)
            expect(io.read).to eq("read me")
          end

          it "read_content returns an IO-like object (for streaming reads)" do
            subject.write_content("/io-test.txt", StringIO.new("streamed"))
            io = subject.read_content("/io-test.txt")
            expect(io).to respond_to(:read)
            expect(io).to respond_to(:each)
          end

          it "raises an error reading a missing file (READ on closed FileId)" do
            expect { subject.read_content("/missing.txt") }.to raise_error(StandardError)
          end

          # ── WRITE ─────────────────────────────────────────────────────────────

          it "writes file content and reflects updated size (WRITE + QUERY_INFO)" do
            subject.write_content("/write-test.txt", StringIO.new("v1"))
            subject.write_content("/write-test.txt", StringIO.new("version2"))
            resource = subject.get_resource("/write-test.txt")
            expect(resource.content_length).to eq(8)
          end

          it "write_content returns a quoted ETag string" do
            etag = subject.write_content("/etag-test.txt", StringIO.new("data"))
            expect(etag).to match(/\A"[^"]+"\z/)
          end

          # ── QUERY_INFO metadata fields required for SMB ───────────────────────

          it "resource has a last_modified Time (required for FileBasicInformation)" do
            subject.write_content("/meta-test.txt", StringIO.new("x"))
            resource = subject.get_resource("/meta-test.txt")
            expect(resource.last_modified).to be_a(Time)
          end

          it "resource has a created_at Time (required for FileBasicInformation)" do
            subject.write_content("/ctime-test.txt", StringIO.new("x"))
            resource = subject.get_resource("/ctime-test.txt")
            expect(resource.created_at).to be_a(Time)
          end

          it "resource has Integer content_length (required for FileStandardInformation)" do
            subject.write_content("/size-test.txt", StringIO.new("12345"))
            resource = subject.get_resource("/size-test.txt")
            expect(resource.content_length).to be_a(Integer)
            expect(resource.content_length).to eq(5)
          end

          it "resource has a non-empty etag String (required for FileInternalInformation)" do
            subject.write_content("/etag-meta.txt", StringIO.new("x"))
            resource = subject.get_resource("/etag-meta.txt")
            expect(resource.etag).to be_a(String)
            expect(resource.etag).not_to be_empty
          end

          it "collection resource returns collection? = true" do
            subject.create_collection("/dir-meta/")
            resource = subject.get_resource("/dir-meta/")
            expect(resource.collection?).to be true
          end

          it "file resource returns collection? = false" do
            subject.write_content("/file-meta.txt", StringIO.new("x"))
            resource = subject.get_resource("/file-meta.txt")
            expect(resource.collection?).to be false
          end

          # ── QUERY_DIRECTORY ───────────────────────────────────────────────────

          it "list_children returns an Array for the root collection" do
            expect(subject.list_children("/")).to be_an(Array)
          end

          it "list_children includes written files (QUERY_DIRECTORY listing)" do
            subject.write_content("/dir-file.txt", StringIO.new("a"))
            children = subject.list_children("/")
            expect(children.map(&:path)).to include("/dir-file.txt")
          end

          it "list_children returns nil for a file path (not a directory)" do
            subject.write_content("/not-a-dir.txt", StringIO.new("x"))
            expect(subject.list_children("/not-a-dir.txt")).to be_nil
          end

          it "list_children includes nested directory (QUERY_DIRECTORY of parent)" do
            subject.create_collection("/nested-dir/")
            subject.write_content("/nested-dir/child.txt", StringIO.new("n"))
            children = subject.list_children("/nested-dir/")
            expect(children.map(&:path)).to include("/nested-dir/child.txt")
          end

          # ── SET_INFO / rename ─────────────────────────────────────────────────

          it "moves (renames) a file (SET_INFO FileRenameInformation)" do
            subject.write_content("/rename-src.txt", StringIO.new("rename me"))
            subject.move("/rename-src.txt", "/rename-dst.txt")
            expect(subject.get_resource("/rename-src.txt")).to be_nil
            expect(subject.get_resource("/rename-dst.txt")).not_to be_nil
          end

          it "moved file preserves content (WRITE + rename + READ)" do
            subject.write_content("/move-content.txt", StringIO.new("preserved"))
            subject.move("/move-content.txt", "/moved.txt")
            expect(subject.read_content("/moved.txt").read).to eq("preserved")
          end

          # ── SET_INFO / delete ─────────────────────────────────────────────────

          it "deletes a file (SET_INFO FileDispositionInformation + CLOSE)" do
            subject.write_content("/delete-me.txt", StringIO.new("gone"))
            subject.delete("/delete-me.txt")
            expect(subject.get_resource("/delete-me.txt")).to be_nil
          end

          it "deletes a directory recursively (CLOSE with delete-on-close on dir)" do
            subject.create_collection("/del-dir/")
            subject.write_content("/del-dir/file.txt", StringIO.new("x"))
            subject.delete("/del-dir/")
            expect(subject.get_resource("/del-dir/")).to be_nil
            expect(subject.get_resource("/del-dir/file.txt")).to be_nil
          end

          it "raises an error deleting a non-existent file" do
            expect { subject.delete("/nonexistent.txt") }.to raise_error(StandardError)
          end

          # ── ETag changes on write ─────────────────────────────────────────────

          it "ETag changes after content is overwritten" do
            subject.write_content("/etag-change.txt", StringIO.new("v1"))
            etag1 = subject.get_resource("/etag-change.txt").etag
            subject.write_content("/etag-change.txt", StringIO.new("v2"))
            etag2 = subject.get_resource("/etag-change.txt").etag
            expect(etag1).not_to eq(etag2)
          end

          # ── Quota (for FileFsSizeInformation) ────────────────────────────────

          it "quota_available_bytes returns Integer or nil" do
            result = subject.quota_available_bytes("/")
            expect(result).to satisfy { |v| v.nil? || v.is_a?(Integer) }
          end

          it "quota_used_bytes returns Integer or nil" do
            result = subject.quota_used_bytes("/")
            expect(result).to satisfy { |v| v.nil? || v.is_a?(Integer) }
          end
        end
      end
    end
  end
end
