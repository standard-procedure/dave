require "spec_helper"
require "rack/test"
require "nokogiri"

RSpec.describe "MOVE" do
  include Rack::Test::Methods

  let(:tmpdir)     { Dir.mktmpdir }
  let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
  let(:app)        { Dave::Server.new(filesystem: filesystem) }

  after { FileUtils.rm_rf(tmpdir) }

  def move(path, headers = {})
    custom_request("MOVE", path, {}, headers)
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

  MOVE_ALLPROP_BODY = <<~XML.freeze
    <?xml version="1.0" encoding="UTF-8"?>
    <D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>
  XML

  # =========================================================================
  # 1. MOVE file to new location → 201, destination exists, source is gone
  # =========================================================================
  context "MOVE file to new location" do
    before { File.write(File.join(tmpdir, "source.txt"), "hello world") }

    it "returns 201 Created" do
      move("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt")
      expect(last_response.status).to eq(201)
    end

    it "creates the file at the destination" do
      move("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt")
      expect(File.exist?(File.join(tmpdir, "dest.txt"))).to be true
    end

    it "removes the source file" do
      move("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt")
      expect(File.exist?(File.join(tmpdir, "source.txt"))).to be false
    end

    it "moves content to the destination" do
      move("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt")
      expect(File.read(File.join(tmpdir, "dest.txt"))).to eq("hello world")
    end
  end

  # =========================================================================
  # 2. MOVE file to existing location (Overwrite: T) → 204, source is gone
  # =========================================================================
  context "MOVE file to existing destination with Overwrite: T" do
    before do
      File.write(File.join(tmpdir, "source.txt"), "new content")
      File.write(File.join(tmpdir, "dest.txt"), "old content")
    end

    it "returns 204 No Content" do
      move("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt", "HTTP_OVERWRITE" => "T")
      expect(last_response.status).to eq(204)
    end

    it "overwrites the destination with source content" do
      move("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt", "HTTP_OVERWRITE" => "T")
      expect(File.read(File.join(tmpdir, "dest.txt"))).to eq("new content")
    end

    it "removes the source file" do
      move("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt", "HTTP_OVERWRITE" => "T")
      expect(File.exist?(File.join(tmpdir, "source.txt"))).to be false
    end
  end

  # =========================================================================
  # 3. MOVE file with Overwrite: F when destination exists → 412
  # =========================================================================
  context "MOVE file with Overwrite: F when destination exists" do
    before do
      File.write(File.join(tmpdir, "source.txt"), "content")
      File.write(File.join(tmpdir, "dest.txt"), "existing")
    end

    it "returns 412 Precondition Failed" do
      move("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt", "HTTP_OVERWRITE" => "F")
      expect(last_response.status).to eq(412)
    end

    it "does not modify the destination" do
      move("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt", "HTTP_OVERWRITE" => "F")
      expect(File.read(File.join(tmpdir, "dest.txt"))).to eq("existing")
    end

    it "does not remove the source" do
      move("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt", "HTTP_OVERWRITE" => "F")
      expect(File.exist?(File.join(tmpdir, "source.txt"))).to be true
    end
  end

  # =========================================================================
  # 4. MOVE non-existent source → 404
  # =========================================================================
  context "MOVE non-existent source" do
    it "returns 404 Not Found" do
      move("/no-such-file.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt")
      expect(last_response.status).to eq(404)
    end
  end

  # =========================================================================
  # 5. MOVE with missing destination parent → 409
  # =========================================================================
  context "MOVE with missing destination parent directory" do
    before { File.write(File.join(tmpdir, "source.txt"), "content") }

    it "returns 409 Conflict" do
      move("/source.txt", "HTTP_DESTINATION" => "http://localhost/no-parent/dest.txt")
      expect(last_response.status).to eq(409)
    end
  end

  # =========================================================================
  # 6. MOVE source to itself → 403
  # =========================================================================
  context "MOVE source to itself" do
    before { File.write(File.join(tmpdir, "source.txt"), "content") }

    it "returns 403 Forbidden" do
      move("/source.txt", "HTTP_DESTINATION" => "http://localhost/source.txt")
      expect(last_response.status).to eq(403)
    end
  end

  # =========================================================================
  # 7. MOVE without Destination header → 400
  # =========================================================================
  context "MOVE without Destination header" do
    before { File.write(File.join(tmpdir, "source.txt"), "content") }

    it "returns 400 Bad Request" do
      move("/source.txt")
      expect(last_response.status).to eq(400)
    end

    it "returns 400 for syntactically invalid Destination URI" do
      File.write(File.join(tmpdir, "source.txt"), "hello")
      # Use rack env directly to bypass Rack header normalisation
      env = Rack::MockRequest.env_for("/source.txt", method: "MOVE", "HTTP_DESTINATION" => "://not a valid uri")
      status, _, _ = app.call(env)
      expect(status).to eq(400)
    end
  end

  # =========================================================================
  # 7b. MOVE with absent Overwrite header defaults to T (overwrite)
  # =========================================================================
  context "MOVE with absent Overwrite header" do
    it "defaults to overwrite when Overwrite header is absent" do
      File.write(File.join(tmpdir, "source.txt"), "hello")
      File.write(File.join(tmpdir, "dest.txt"), "existing")
      env = Rack::MockRequest.env_for("/source.txt", method: "MOVE", "HTTP_DESTINATION" => "http://example.org/dest.txt")
      status, _, _ = app.call(env)
      expect(status).to eq(204)
      expect(File.exist?(File.join(tmpdir, "dest.txt"))).to be true
      expect(File.exist?(File.join(tmpdir, "source.txt"))).to be false
    end
  end

  # =========================================================================
  # 8. MOVE collection → 201, all members moved, source collection is gone
  # =========================================================================
  context "MOVE collection" do
    before do
      Dir.mkdir(File.join(tmpdir, "srcdir"))
      File.write(File.join(tmpdir, "srcdir", "child.txt"), "child content")
      Dir.mkdir(File.join(tmpdir, "srcdir", "subdir"))
      File.write(File.join(tmpdir, "srcdir", "subdir", "grandchild.txt"), "grandchild")
    end

    it "returns 201 Created" do
      move("/srcdir", "HTTP_DESTINATION" => "http://localhost/dstdir")
      expect(last_response.status).to eq(201)
    end

    it "creates the destination collection with all members" do
      move("/srcdir", "HTTP_DESTINATION" => "http://localhost/dstdir")
      expect(File.exist?(File.join(tmpdir, "dstdir", "child.txt"))).to be true
      expect(File.exist?(File.join(tmpdir, "dstdir", "subdir", "grandchild.txt"))).to be true
    end

    it "removes the source collection" do
      move("/srcdir", "HTTP_DESTINATION" => "http://localhost/dstdir")
      expect(File.exist?(File.join(tmpdir, "srcdir"))).to be false
    end
  end

  # =========================================================================
  # lock enforcement
  # =========================================================================
  context "lock enforcement" do
    LOCKINFO_EXCLUSIVE_MOVE = <<~XML.freeze
      <?xml version="1.0" encoding="UTF-8"?>
      <D:lockinfo xmlns:D="DAV:">
        <D:lockscope><D:exclusive/></D:lockscope>
        <D:locktype><D:write/></D:locktype>
      </D:lockinfo>
    XML

    def lock_token_for_move(path)
      env = { "rack.input" => StringIO.new(LOCKINFO_EXCLUSIVE_MOVE) }
      custom_request("LOCK", path, {}, env)
      last_response.headers["Lock-Token"].match(/<(urn:uuid:[^>]+)>/)[1]
    end

    context "with a locked source" do
      before { File.write(File.join(tmpdir, "source.txt"), "hello") }

      it "MOVE with locked source and no If header returns 423 Locked" do
        lock_token_for_move("/source.txt")
        move("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt")
        expect(last_response.status).to eq(423)
      end

      it "MOVE with locked source and correct token in If header returns 201" do
        token = lock_token_for_move("/source.txt")
        move("/source.txt",
          "HTTP_DESTINATION" => "http://localhost/dest.txt",
          "HTTP_IF"          => "(<#{token}>)"
        )
        expect(last_response.status).to eq(201)
      end
    end

    context "with a locked destination" do
      before do
        File.write(File.join(tmpdir, "source.txt"), "hello")
        File.write(File.join(tmpdir, "dest.txt"), "existing")
      end

      it "MOVE with locked destination and no If header returns 423 Locked" do
        lock_token_for_move("/dest.txt")
        move("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt")
        expect(last_response.status).to eq(423)
      end

      it "MOVE with locked destination and correct token in If header returns 204" do
        token = lock_token_for_move("/dest.txt")
        move("/source.txt",
          "HTTP_DESTINATION" => "http://localhost/dest.txt",
          "HTTP_IF"          => "(<#{token}>)"
        )
        expect(last_response.status).to eq(204)
      end
    end
  end

  # =========================================================================
  # 9. Dead properties travel with MOVE
  # =========================================================================
  context "dead properties travel with MOVE" do
    before do
      File.write(File.join(tmpdir, "source.txt"), "hello")
      filesystem.set_properties("/source.txt", "{http://example.com/}author" => "Alice")
    end

    it "moves dead properties to the destination" do
      move("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt")
      expect(last_response.status).to eq(201)
      props = filesystem.get_properties("/dest.txt")
      expect(props["{http://example.com/}author"]).to eq("Alice")
    end

    it "PROPFIND on destination shows moved dead property" do
      move("/source.txt", "HTTP_DESTINATION" => "http://localhost/dest.txt")

      propfind("/dest.txt", body: MOVE_ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      author = doc.at_xpath("//*[local-name()='author' and namespace-uri()='http://example.com/']")
      expect(author).not_to be_nil
      expect(author.text).to eq("Alice")
    end
  end
end
