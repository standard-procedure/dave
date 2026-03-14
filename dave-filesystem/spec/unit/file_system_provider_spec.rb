require "spec_helper"
require "tmpdir"
require "stringio"

RSpec.describe Dave::FileSystemProvider do
  let(:tmpdir) { Dir.mktmpdir }
  subject(:provider) { described_class.new(root: tmpdir) }

  after { FileUtils.rm_rf(tmpdir) }

  # ──────────────────────────────────────────────
  # Group C1: get_resource / list_children
  # ──────────────────────────────────────────────

  describe "#get_resource" do
    context "when path does not exist" do
      it "returns nil" do
        expect(provider.get_resource("/nonexistent.txt")).to be_nil
      end
    end

    context "when path is an existing file" do
      before { File.write(File.join(tmpdir, "hello.txt"), "world") }

      it "returns a Dave::Resource" do
        expect(provider.get_resource("/hello.txt")).to be_a(Dave::Resource)
      end

      it "has the correct path" do
        expect(provider.get_resource("/hello.txt").path).to eq("/hello.txt")
      end

      it "is not a collection" do
        expect(provider.get_resource("/hello.txt").collection?).to be false
      end

      it "has content_length matching the file size" do
        expect(provider.get_resource("/hello.txt").content_length).to eq(5)
      end

      it "has a non-nil content_type" do
        expect(provider.get_resource("/hello.txt").content_type).not_to be_nil
      end

      it "has a quoted etag" do
        etag = provider.get_resource("/hello.txt").etag
        expect(etag).to match(/\A"[a-f0-9]+"\z/)
      end

      it "has a last_modified Time" do
        expect(provider.get_resource("/hello.txt").last_modified).to be_a(Time)
      end

      it "has a created_at Time" do
        expect(provider.get_resource("/hello.txt").created_at).to be_a(Time)
      end
    end

    context "when path is an existing directory" do
      before { Dir.mkdir(File.join(tmpdir, "mydir")) }

      it "returns a Dave::Resource for a path with trailing slash" do
        expect(provider.get_resource("/mydir/")).to be_a(Dave::Resource)
      end

      it "returns a Dave::Resource for a path without trailing slash too" do
        expect(provider.get_resource("/mydir")).to be_a(Dave::Resource)
      end

      it "is a collection" do
        expect(provider.get_resource("/mydir/").collection?).to be true
      end

      it "has nil content_type" do
        expect(provider.get_resource("/mydir/").content_type).to be_nil
      end

      it "has nil content_length" do
        expect(provider.get_resource("/mydir/").content_length).to be_nil
      end

      it "has a quoted etag" do
        etag = provider.get_resource("/mydir/").etag
        expect(etag).to match(/\A"[a-f0-9]+"\z/)
      end
    end
  end

  describe "#list_children" do
    context "when path does not exist" do
      it "returns nil" do
        expect(provider.list_children("/nonexistent/")).to be_nil
      end
    end

    context "when path is a file (not a directory)" do
      before { File.write(File.join(tmpdir, "file.txt"), "data") }

      it "returns nil" do
        expect(provider.list_children("/file.txt")).to be_nil
      end
    end

    context "when path is a directory" do
      before do
        File.write(File.join(tmpdir, "a.txt"), "a")
        File.write(File.join(tmpdir, "b.txt"), "b")
        Dir.mkdir(File.join(tmpdir, "subdir"))
      end

      it "returns an Array" do
        expect(provider.list_children("/")).to be_an(Array)
      end

      it "does not include . or .." do
        paths = provider.list_children("/").map(&:path)
        expect(paths).not_to include(".", "..")
        expect(paths).not_to include("/.", "/..")
      end

      it "includes the expected file paths" do
        paths = provider.list_children("/").map(&:path)
        expect(paths).to include("/a.txt", "/b.txt")
      end

      it "includes the subdirectory" do
        paths = provider.list_children("/").map(&:path)
        expect(paths).to include("/subdir/")
      end

      it "returns Dave::Resource objects" do
        children = provider.list_children("/")
        expect(children).to all(be_a(Dave::Resource))
      end
    end
  end

  # ──────────────────────────────────────────────
  # Group C2: read_content / write_content
  # ──────────────────────────────────────────────

  describe "#read_content" do
    context "when path does not exist" do
      it "raises Dave::NotFoundError" do
        expect { provider.read_content("/missing.txt") }.to raise_error(Dave::NotFoundError)
      end
    end

    context "when path exists" do
      before { File.write(File.join(tmpdir, "data.txt"), "hello world") }

      it "returns an IO-like object" do
        io = provider.read_content("/data.txt")
        expect(io).to respond_to(:read)
        io.close
      end

      it "can read the file content" do
        io = provider.read_content("/data.txt")
        expect(io.read).to eq("hello world")
        io.close
      end
    end
  end

  describe "#write_content" do
    context "when parent directory exists" do
      it "writes the content to disk" do
        provider.write_content("/newfile.txt", StringIO.new("test content"))
        expect(File.read(File.join(tmpdir, "newfile.txt"))).to eq("test content")
      end

      it "returns a quoted ETag string" do
        etag = provider.write_content("/newfile.txt", StringIO.new("test"))
        expect(etag).to match(/\A"[a-f0-9]+"\z/)
      end

      it "overwrites existing content" do
        provider.write_content("/overwrite.txt", StringIO.new("first"))
        provider.write_content("/overwrite.txt", StringIO.new("second"))
        expect(File.read(File.join(tmpdir, "overwrite.txt"))).to eq("second")
      end

      it "returns different ETags for different content" do
        etag1 = provider.write_content("/etag.txt", StringIO.new("v1"))
        etag2 = provider.write_content("/etag.txt", StringIO.new("v2"))
        expect(etag1).not_to eq(etag2)
      end
    end

    context "when parent directory does not exist" do
      it "raises Dave::NotFoundError" do
        expect {
          provider.write_content("/missing-parent/file.txt", StringIO.new("x"))
        }.to raise_error(Dave::NotFoundError)
      end
    end
  end

  # ──────────────────────────────────────────────
  # Group C3: create_collection / delete
  # ──────────────────────────────────────────────

  describe "#create_collection" do
    context "when parent exists" do
      it "creates the directory" do
        provider.create_collection("/newdir/")
        expect(File.directory?(File.join(tmpdir, "newdir"))).to be true
      end

      it "also works without trailing slash" do
        provider.create_collection("/newdir2")
        expect(File.directory?(File.join(tmpdir, "newdir2"))).to be true
      end
    end

    context "when path already exists" do
      before { Dir.mkdir(File.join(tmpdir, "existing")) }

      it "raises Dave::AlreadyExistsError" do
        expect { provider.create_collection("/existing/") }.to raise_error(Dave::AlreadyExistsError)
      end
    end

    context "when parent directory does not exist" do
      it "raises Dave::NotFoundError" do
        expect { provider.create_collection("/missing-parent/newdir/") }.to raise_error(Dave::NotFoundError)
      end
    end
  end

  describe "#delete" do
    context "when path does not exist" do
      it "raises Dave::NotFoundError" do
        expect { provider.delete("/nonexistent.txt") }.to raise_error(Dave::NotFoundError)
      end
    end

    context "when path is a file" do
      before { File.write(File.join(tmpdir, "todelete.txt"), "bye") }

      it "deletes the file" do
        provider.delete("/todelete.txt")
        expect(File.exist?(File.join(tmpdir, "todelete.txt"))).to be false
      end

      it "returns an empty array" do
        result = provider.delete("/todelete.txt")
        expect(result).to eq([])
      end
    end

    context "when path is a directory" do
      before do
        Dir.mkdir(File.join(tmpdir, "mydir"))
        File.write(File.join(tmpdir, "mydir", "file.txt"), "x")
      end

      it "deletes the directory recursively" do
        provider.delete("/mydir/")
        expect(File.exist?(File.join(tmpdir, "mydir"))).to be false
      end

      it "returns an empty array" do
        result = provider.delete("/mydir/")
        expect(result).to eq([])
      end
    end
  end

  # ──────────────────────────────────────────────
  # Group C4: supports_locking? / quota methods
  # ──────────────────────────────────────────────

  describe "#supports_locking?" do
    it "returns false" do
      expect(provider.supports_locking?).to be false
    end
  end

  describe "#quota_available_bytes" do
    it "returns nil" do
      expect(provider.quota_available_bytes("/")).to be_nil
    end
  end

  describe "#quota_used_bytes" do
    it "returns nil" do
      expect(provider.quota_used_bytes("/")).to be_nil
    end
  end

  # ──────────────────────────────────────────────
  # Phase 2+ stubs
  # ──────────────────────────────────────────────

  describe "#get_properties" do
    before { File.write(File.join(tmpdir, "file.txt"), "x") }

    it "returns an empty hash" do
      expect(provider.get_properties("/file.txt")).to eq({})
    end
  end

  describe "#set_properties" do
    before { File.write(File.join(tmpdir, "file.txt"), "x") }

    it "returns the properties passed in" do
      props = { "{http://example.com/}foo" => "<foo/>" }
      expect(provider.set_properties("/file.txt", props)).to eq(props)
    end
  end

  describe "#delete_properties" do
    before { File.write(File.join(tmpdir, "file.txt"), "x") }

    it "returns nil" do
      expect(provider.delete_properties("/file.txt", ["{http://example.com/}foo"])).to be_nil
    end
  end

  describe "#copy" do
    before { File.write(File.join(tmpdir, "src.txt"), "hello") }

    it "copies the file to the destination" do
      provider.copy("/src.txt", "/dst.txt")
      expect(File.read(File.join(tmpdir, "dst.txt"))).to eq("hello")
    end
  end

  describe "#move" do
    before { File.write(File.join(tmpdir, "src.txt"), "hello") }

    it "moves the file to the destination" do
      provider.move("/src.txt", "/dst.txt")
      expect(File.exist?(File.join(tmpdir, "src.txt"))).to be false
      expect(File.read(File.join(tmpdir, "dst.txt"))).to eq("hello")
    end
  end

  describe "#lock" do
    it "raises NotImplementedError" do
      expect { provider.lock("/file.txt", scope: :exclusive, depth: :zero) }.to raise_error(NotImplementedError)
    end
  end

  describe "#unlock" do
    it "raises NotImplementedError" do
      expect { provider.unlock("/file.txt", "urn:uuid:abc") }.to raise_error(NotImplementedError)
    end
  end

  describe "#get_lock" do
    it "raises NotImplementedError" do
      expect { provider.get_lock("/file.txt") }.to raise_error(NotImplementedError)
    end
  end

  # ──────────────────────────────────────────────
  # Security: path traversal prevention
  # ──────────────────────────────────────────────

  describe "security" do
    it "raises NotFoundError for path traversal attempts via get_resource" do
      expect { provider.get_resource("/../../../etc/passwd") }
        .to raise_error(Dave::NotFoundError)
    end

    it "raises NotFoundError for path traversal attempts via read_content" do
      expect { provider.read_content("/../../../etc/passwd") }
        .to raise_error(Dave::NotFoundError)
    end
  end

  # ──────────────────────────────────────────────
  # Compliance tests
  # ──────────────────────────────────────────────

  include Dave::FileSystemInterface::ComplianceTests
end
