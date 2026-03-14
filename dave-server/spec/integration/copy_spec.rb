require "spec_helper"
require "rack/test"
require "nokogiri"

RSpec.describe "COPY" do
  include Rack::Test::Methods

  let(:tmpdir)     { Dir.mktmpdir }
  let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
  let(:app)        { Dave::Server.new(filesystem: filesystem) }

  after { FileUtils.rm_rf(tmpdir) }

  def copy(path, headers = {})
    custom_request("COPY", path, {}, headers)
  end

  def propfind(path, body: nil, headers: {})
    rack_env = { "rack.input" => StringIO.new(body.to_s) }.merge(headers)
    custom_request("PROPFIND", path, {}, rack_env)
  end

  def parse_xml(body)
    Nokogiri::XML(body)
  end

  def dav_ns
    { "D" => "DAV:" }
  end

  COPY_ALLPROP_BODY = <<~XML.freeze
    <?xml version="1.0" encoding="UTF-8"?>
    <D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>
  XML

  # =========================================================================
  # 1. COPY file to new location → 201, file exists at destination
  # =========================================================================
  context "COPY file to new location" do
    before { File.write(File.join(tmpdir, "source.txt"), "hello world") }

    it "returns 201 Created" do
      copy("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt")
      expect(last_response.status).to eq(201)
    end

    it "creates the file at the destination" do
      copy("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt")
      expect(File.exist?(File.join(tmpdir, "dest.txt"))).to be true
    end

    it "copies the content to the destination" do
      copy("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt")
      expect(File.read(File.join(tmpdir, "dest.txt"))).to eq("hello world")
    end
  end

  # =========================================================================
  # 2. COPY file to existing location (overwrite: T) → 204, destination updated
  # =========================================================================
  context "COPY file to existing destination with Overwrite: T" do
    before do
      File.write(File.join(tmpdir, "source.txt"), "new content")
      File.write(File.join(tmpdir, "dest.txt"), "old content")
    end

    it "returns 204 No Content" do
      copy("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt", "HTTP_OVERWRITE" => "T")
      expect(last_response.status).to eq(204)
    end

    it "overwrites the destination with source content" do
      copy("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt", "HTTP_OVERWRITE" => "T")
      expect(File.read(File.join(tmpdir, "dest.txt"))).to eq("new content")
    end
  end

  # =========================================================================
  # 3. COPY file with Overwrite: F when destination exists → 412
  # =========================================================================
  context "COPY file with Overwrite: F when destination exists" do
    before do
      File.write(File.join(tmpdir, "source.txt"), "content")
      File.write(File.join(tmpdir, "dest.txt"), "existing")
    end

    it "returns 412 Precondition Failed" do
      copy("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt", "HTTP_OVERWRITE" => "F")
      expect(last_response.status).to eq(412)
    end

    it "does not modify the destination" do
      copy("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt", "HTTP_OVERWRITE" => "F")
      expect(File.read(File.join(tmpdir, "dest.txt"))).to eq("existing")
    end
  end

  # =========================================================================
  # 4. COPY non-existent source → 404
  # =========================================================================
  context "COPY non-existent source" do
    it "returns 404 Not Found" do
      copy("/no-such-file.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt")
      expect(last_response.status).to eq(404)
    end
  end

  # =========================================================================
  # 5. COPY with missing destination parent → 409
  # =========================================================================
  context "COPY with missing destination parent directory" do
    before { File.write(File.join(tmpdir, "source.txt"), "content") }

    it "returns 409 Conflict" do
      copy("/source.txt", "HTTP_DESTINATION" => "http://localhost/no-parent/dest.txt")
      expect(last_response.status).to eq(409)
    end
  end

  # =========================================================================
  # 6. COPY source to itself (same path) → 403
  # =========================================================================
  context "COPY source to itself" do
    before { File.write(File.join(tmpdir, "source.txt"), "content") }

    it "returns 403 Forbidden" do
      copy("/source.txt", "HTTP_DESTINATION" => "http://localhost/source.txt")
      expect(last_response.status).to eq(403)
    end
  end

  # =========================================================================
  # 7. COPY without Destination header → 400
  # =========================================================================
  context "COPY without Destination header" do
    before { File.write(File.join(tmpdir, "source.txt"), "content") }

    it "returns 400 Bad Request" do
      copy("/source.txt")
      expect(last_response.status).to eq(400)
    end
  end

  # =========================================================================
  # 7b. COPY with Depth: 1 → 400 (invalid depth value for COPY)
  # =========================================================================
  context "COPY with Depth: 1" do
    before { File.write(File.join(tmpdir, "source.txt"), "hello") }

    it "returns 400 Bad Request" do
      copy("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt", "HTTP_DEPTH" => "1")
      expect(last_response.status).to eq(400)
    end
  end

  # =========================================================================
  # 8. COPY collection with Depth: 0 → 201, only empty collection created
  # =========================================================================
  context "COPY collection with Depth: 0" do
    before do
      Dir.mkdir(File.join(tmpdir, "srcdir"))
      File.write(File.join(tmpdir, "srcdir", "child.txt"), "child content")
    end

    it "returns 201 Created" do
      copy("/srcdir", "HTTP_DESTINATION" => "http://localhost/dstdir", "HTTP_DEPTH" => "0")
      expect(last_response.status).to eq(201)
    end

    it "creates the destination collection" do
      copy("/srcdir", "HTTP_DESTINATION" => "http://localhost/dstdir", "HTTP_DEPTH" => "0")
      expect(File.directory?(File.join(tmpdir, "dstdir"))).to be true
    end

    it "does not copy collection members" do
      copy("/srcdir", "HTTP_DESTINATION" => "http://localhost/dstdir", "HTTP_DEPTH" => "0")
      expect(File.exist?(File.join(tmpdir, "dstdir", "child.txt"))).to be false
    end
  end

  # =========================================================================
  # 9. COPY collection with Depth: infinity (default) → 201, all members copied
  # =========================================================================
  context "COPY collection with Depth: infinity (default)" do
    before do
      Dir.mkdir(File.join(tmpdir, "srcdir"))
      File.write(File.join(tmpdir, "srcdir", "child.txt"), "child content")
      Dir.mkdir(File.join(tmpdir, "srcdir", "subdir"))
      File.write(File.join(tmpdir, "srcdir", "subdir", "grandchild.txt"), "grandchild")
    end

    it "returns 201 Created" do
      copy("/srcdir", "HTTP_DESTINATION" => "http://localhost/dstdir")
      expect(last_response.status).to eq(201)
    end

    it "copies all members recursively" do
      copy("/srcdir", "HTTP_DESTINATION" => "http://localhost/dstdir")
      expect(File.exist?(File.join(tmpdir, "dstdir", "child.txt"))).to be true
      expect(File.exist?(File.join(tmpdir, "dstdir", "subdir", "grandchild.txt"))).to be true
    end
  end

  # =========================================================================
  # 10. Dead properties travel with copy
  # =========================================================================
  context "dead properties travel with COPY" do
    before do
      File.write(File.join(tmpdir, "source.txt"), "hello")
      filesystem.set_properties("/source.txt", "{http://example.com/}author" => "Alice")
    end

    it "copies dead properties to the destination" do
      copy("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt")
      expect(last_response.status).to eq(201)
      props = filesystem.get_properties("/dest.txt")
      expect(props["{http://example.com/}author"]).to eq("Alice")
    end

    it "PROPFIND on destination shows copied dead property" do
      copy("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt")

      propfind("/dest.txt", body: COPY_ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      author = doc.at_xpath("//*[local-name()='author' and namespace-uri()='http://example.com/']")
      expect(author).not_to be_nil
      expect(author.text).to eq("Alice")
    end
  end
end
