require "spec_helper"
require "rack/test"
require "nokogiri"

RSpec.describe "LOCK" do
  include Rack::Test::Methods

  let(:tmpdir)     { Dir.mktmpdir }
  let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
  let(:app)        { Dave::Server.new(filesystem: filesystem) }

  after { FileUtils.rm_rf(tmpdir) }

  def lock(path, headers = {}, body = nil)
    env = { "rack.input" => StringIO.new(body.to_s) }.merge(headers)
    custom_request("LOCK", path, {}, env)
  end

  def parse_xml(body)
    Nokogiri::XML(body)
  end

  def dav_ns
    { "D" => "DAV:" }
  end

  LOCKINFO_EXCLUSIVE = <<~XML.freeze
    <?xml version="1.0" encoding="UTF-8"?>
    <D:lockinfo xmlns:D="DAV:">
      <D:lockscope><D:exclusive/></D:lockscope>
      <D:locktype><D:write/></D:locktype>
    </D:lockinfo>
  XML

  LOCKINFO_WITH_OWNER = <<~XML.freeze
    <?xml version="1.0" encoding="UTF-8"?>
    <D:lockinfo xmlns:D="DAV:">
      <D:lockscope><D:exclusive/></D:lockscope>
      <D:locktype><D:write/></D:locktype>
      <D:owner>
        <D:href>http://example.org/~user</D:href>
      </D:owner>
    </D:lockinfo>
  XML

  LOCKINFO_SHARED = <<~XML.freeze
    <?xml version="1.0" encoding="UTF-8"?>
    <D:lockinfo xmlns:D="DAV:">
      <D:lockscope><D:shared/></D:lockscope>
      <D:locktype><D:write/></D:locktype>
    </D:lockinfo>
  XML

  # ===========================================================================
  # 1. LOCK existing file → 200, Lock-Token header, XML body with activelock
  # ===========================================================================
  context "LOCK existing file" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns 200 OK" do
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
      expect(last_response.status).to eq(200)
    end

    it "returns a Lock-Token header" do
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
      expect(last_response.headers["Lock-Token"]).to match(/<urn:uuid:[^>]+>/)
    end

    it "returns XML body with D:prop root" do
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
      doc = parse_xml(last_response.body)
      expect(doc.root.name).to eq("prop")
      expect(doc.root.namespace.href).to eq("DAV:")
    end

    it "returns XML body with activelock element" do
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
      doc = parse_xml(last_response.body)
      activelock = doc.at_xpath("//D:activelock", dav_ns)
      expect(activelock).not_to be_nil
    end

    it "returns activelock with correct locktype" do
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
      doc = parse_xml(last_response.body)
      write_el = doc.at_xpath("//D:activelock/D:locktype/D:write", dav_ns)
      expect(write_el).not_to be_nil
    end

    it "returns activelock with correct lockscope (exclusive)" do
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
      doc = parse_xml(last_response.body)
      excl_el = doc.at_xpath("//D:activelock/D:lockscope/D:exclusive", dav_ns)
      expect(excl_el).not_to be_nil
    end

    it "returns activelock with a locktoken href containing urn:uuid" do
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
      doc = parse_xml(last_response.body)
      token_href = doc.at_xpath("//D:activelock/D:locktoken/D:href", dav_ns)
      expect(token_href).not_to be_nil
      expect(token_href.text).to match(/\Aurn:uuid:/)
    end

    it "returns activelock with a lockroot href matching the path" do
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
      doc = parse_xml(last_response.body)
      lockroot_href = doc.at_xpath("//D:activelock/D:lockroot/D:href", dav_ns)
      expect(lockroot_href).not_to be_nil
      expect(lockroot_href.text).to eq("/file.txt")
    end

    it "returns default timeout of Second-3600" do
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
      doc = parse_xml(last_response.body)
      timeout_el = doc.at_xpath("//D:activelock/D:timeout", dav_ns)
      expect(timeout_el.text).to eq("Second-3600")
    end

    it "returns default depth of infinity" do
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
      doc = parse_xml(last_response.body)
      depth_el = doc.at_xpath("//D:activelock/D:depth", dav_ns)
      expect(depth_el.text).to eq("infinity")
    end

    it "includes the owner element when specified" do
      lock("/file.txt", {}, LOCKINFO_WITH_OWNER)
      doc = parse_xml(last_response.body)
      owner_href = doc.at_xpath("//D:activelock/D:owner/D:href", dav_ns)
      expect(owner_href).not_to be_nil
      expect(owner_href.text).to eq("http://example.org/~user")
    end
  end

  # ===========================================================================
  # 2. LOCK non-existent file in existing parent → 201 Created, creates empty resource
  # ===========================================================================
  context "LOCK non-existent file in existing parent" do
    it "returns 201 Created" do
      lock("/new-file.txt", {}, LOCKINFO_EXCLUSIVE)
      expect(last_response.status).to eq(201)
    end

    it "creates the file as an empty resource" do
      lock("/new-file.txt", {}, LOCKINFO_EXCLUSIVE)
      expect(File.exist?(File.join(tmpdir, "new-file.txt"))).to be true
      expect(File.read(File.join(tmpdir, "new-file.txt"))).to eq("")
    end

    it "returns a Lock-Token header" do
      lock("/new-file.txt", {}, LOCKINFO_EXCLUSIVE)
      expect(last_response.headers["Lock-Token"]).to match(/<urn:uuid:[^>]+>/)
    end
  end

  # ===========================================================================
  # 3. LOCK non-existent file in non-existent parent → 409 Conflict
  # ===========================================================================
  context "LOCK non-existent file in non-existent parent" do
    it "returns 409 Conflict" do
      lock("/no-parent/file.txt", {}, LOCKINFO_EXCLUSIVE)
      expect(last_response.status).to eq(409)
    end
  end

  # ===========================================================================
  # 4. LOCK with explicit Depth: 0 → response depth element is "0"
  # ===========================================================================
  context "LOCK with Depth: 0" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns depth 0 in the response" do
      lock("/file.txt", { "HTTP_DEPTH" => "0" }, LOCKINFO_EXCLUSIVE)
      doc = parse_xml(last_response.body)
      depth_el = doc.at_xpath("//D:activelock/D:depth", dav_ns)
      expect(depth_el.text).to eq("0")
    end
  end

  # ===========================================================================
  # 5. LOCK with explicit Depth: infinity → response depth element is "infinity"
  # ===========================================================================
  context "LOCK with Depth: infinity" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns depth infinity in the response" do
      lock("/file.txt", { "HTTP_DEPTH" => "infinity" }, LOCKINFO_EXCLUSIVE)
      doc = parse_xml(last_response.body)
      depth_el = doc.at_xpath("//D:activelock/D:depth", dav_ns)
      expect(depth_el.text).to eq("infinity")
    end
  end

  # ===========================================================================
  # 6. LOCK with Timeout: Second-3600
  # ===========================================================================
  context "LOCK with Timeout: Second-3600" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns Second-3600 timeout" do
      lock("/file.txt", { "HTTP_TIMEOUT" => "Second-3600" }, LOCKINFO_EXCLUSIVE)
      doc = parse_xml(last_response.body)
      timeout_el = doc.at_xpath("//D:activelock/D:timeout", dav_ns)
      expect(timeout_el.text).to eq("Second-3600")
    end
  end

  # ===========================================================================
  # 7. LOCK with Timeout: Infinite
  # ===========================================================================
  context "LOCK with Timeout: Infinite" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns Infinite timeout" do
      lock("/file.txt", { "HTTP_TIMEOUT" => "Infinite" }, LOCKINFO_EXCLUSIVE)
      doc = parse_xml(last_response.body)
      timeout_el = doc.at_xpath("//D:activelock/D:timeout", dav_ns)
      expect(timeout_el.text).to eq("Infinite")
    end
  end

  # ===========================================================================
  # 8. Second LOCK on same file (exclusive conflict) → 423 Locked
  # ===========================================================================
  context "second LOCK on already-exclusively-locked file" do
    before do
      File.write(File.join(tmpdir, "file.txt"), "hello")
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
    end

    it "returns 423 Locked" do
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
      expect(last_response.status).to eq(423)
    end

    it "returns an XML error body with no-conflicting-lock" do
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
      doc = parse_xml(last_response.body)
      error_el = doc.at_xpath("//D:error/D:no-conflicting-lock", dav_ns)
      expect(error_el).not_to be_nil
    end
  end

  # ===========================================================================
  # 9. LOCK refresh (If header, no body) → 200, no Lock-Token header
  # ===========================================================================
  context "LOCK refresh with valid token" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    let(:lock_token) do
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
      token_header = last_response.headers["Lock-Token"]
      # Extract urn:uuid:... from <urn:uuid:...>
      token_header.match(/<(urn:uuid:[^>]+)>/)[1]
    end

    it "returns 200 OK" do
      token = lock_token
      lock("/file.txt", { "HTTP_IF" => "(<#{token}>)" }, nil)
      expect(last_response.status).to eq(200)
    end

    it "does NOT return a Lock-Token header" do
      token = lock_token
      lock("/file.txt", { "HTTP_IF" => "(<#{token}>)" }, nil)
      expect(last_response.headers["Lock-Token"]).to be_nil
    end

    it "returns XML body with activelock" do
      token = lock_token
      lock("/file.txt", { "HTTP_IF" => "(<#{token}>)" }, nil)
      doc = parse_xml(last_response.body)
      activelock = doc.at_xpath("//D:activelock", dav_ns)
      expect(activelock).not_to be_nil
    end
  end

  # ===========================================================================
  # 10. LOCK refresh with invalid/unknown token → 412 Precondition Failed
  # ===========================================================================
  context "LOCK refresh with invalid token" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns 412 Precondition Failed" do
      lock("/file.txt", { "HTTP_IF" => "(<urn:uuid:00000000-0000-0000-0000-000000000000>)" }, nil)
      expect(last_response.status).to eq(412)
    end
  end

  # ===========================================================================
  # 11. LOCK a directory (collection) → 200
  # ===========================================================================
  context "LOCK a collection" do
    before { Dir.mkdir(File.join(tmpdir, "mydir")) }

    it "returns 200 OK" do
      lock("/mydir", {}, LOCKINFO_EXCLUSIVE)
      expect(last_response.status).to eq(200)
    end

    it "returns a Lock-Token header" do
      lock("/mydir", {}, LOCKINFO_EXCLUSIVE)
      expect(last_response.headers["Lock-Token"]).to match(/<urn:uuid:[^>]+>/)
    end
  end

  # ===========================================================================
  # 12. Shared lock behavior
  # ===========================================================================
  context "two shared locks on the same resource" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "first shared lock returns 200 OK" do
      lock("/file.txt", {}, LOCKINFO_SHARED)
      expect(last_response.status).to eq(200)
    end

    it "second shared lock also returns 200 OK" do
      lock("/file.txt", {}, LOCKINFO_SHARED)
      lock("/file.txt", {}, LOCKINFO_SHARED)
      expect(last_response.status).to eq(200)
    end
  end

  context "shared lock then exclusive lock" do
    before do
      File.write(File.join(tmpdir, "file.txt"), "hello")
      lock("/file.txt", {}, LOCKINFO_SHARED)
    end

    it "returns 423 Locked" do
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
      expect(last_response.status).to eq(423)
    end
  end

  context "exclusive lock then shared lock" do
    before do
      File.write(File.join(tmpdir, "file.txt"), "hello")
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
    end

    it "returns 423 Locked" do
      lock("/file.txt", {}, LOCKINFO_SHARED)
      expect(last_response.status).to eq(423)
    end
  end

  # ===========================================================================
  # 13. LOCK refresh with token belonging to a different path → 412
  # ===========================================================================
  context "LOCK refresh with token belonging to a different path" do
    before do
      File.write(File.join(tmpdir, "file.txt"), "hello")
      File.write(File.join(tmpdir, "other.txt"), "world")
    end

    let(:other_token) do
      lock("/other.txt", {}, LOCKINFO_EXCLUSIVE)
      token_header = last_response.headers["Lock-Token"]
      token_header.match(/<(urn:uuid:[^>]+)>/)[1]
    end

    it "returns 412 Precondition Failed" do
      token = other_token
      lock("/file.txt", { "HTTP_IF" => "(<#{token}>)" }, nil)
      expect(last_response.status).to eq(412)
    end
  end

  # ===========================================================================
  # 15. LOCK with missing XML body (no If header) → 400 Bad Request
  # ===========================================================================
  context "LOCK with no body and no If header" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns 400 Bad Request" do
      lock("/file.txt", {}, nil)
      expect(last_response.status).to eq(400)
    end
  end

  # ===========================================================================
  # 16. LOCK with malformed XML body → 400 Bad Request
  # ===========================================================================
  context "LOCK with malformed XML body" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns 400 Bad Request" do
      lock("/file.txt", {}, "<not valid xml")
      expect(last_response.status).to eq(400)
    end
  end
end
