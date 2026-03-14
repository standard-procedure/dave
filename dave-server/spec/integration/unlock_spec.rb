require "spec_helper"
require "rack/test"
require "nokogiri"

RSpec.describe "UNLOCK" do
  include Rack::Test::Methods

  let(:tmpdir)     { Dir.mktmpdir }
  let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
  let(:app)        { Dave::Server.new(filesystem: filesystem) }

  after { FileUtils.rm_rf(tmpdir) }

  def lock(path, headers = {}, body = nil)
    env = { "rack.input" => StringIO.new(body.to_s) }.merge(headers)
    custom_request("LOCK", path, {}, env)
  end

  def unlock(path, headers = {})
    env = { "rack.input" => StringIO.new("") }.merge(headers)
    custom_request("UNLOCK", path, {}, env)
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

  # Helper: acquire a lock on the given path and return the raw token string
  def acquire_lock(path)
    lock(path, {}, LOCKINFO_EXCLUSIVE)
    token_header = last_response.headers["Lock-Token"]
    token_header.match(/<(urn:uuid:[^>]+)>/)[1]
  end

  # ===========================================================================
  # 1. UNLOCK with valid token for the locked path → 204 No Content
  # ===========================================================================
  context "UNLOCK with valid token for the locked path" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns 204 No Content" do
      token = acquire_lock("/file.txt")
      unlock("/file.txt", { "HTTP_LOCK_TOKEN" => "<#{token}>" })
      expect(last_response.status).to eq(204)
    end

    it "returns an empty body" do
      token = acquire_lock("/file.txt")
      unlock("/file.txt", { "HTTP_LOCK_TOKEN" => "<#{token}>" })
      expect(last_response.body).to be_empty
    end
  end

  # ===========================================================================
  # 2. UNLOCK removes the lock (verify with subsequent LOCK that succeeds)
  # ===========================================================================
  context "UNLOCK removes the lock" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "allows re-locking after unlock" do
      token = acquire_lock("/file.txt")
      unlock("/file.txt", { "HTTP_LOCK_TOKEN" => "<#{token}>" })
      expect(last_response.status).to eq(204)

      # Now re-lock — should succeed with 200
      lock("/file.txt", {}, LOCKINFO_EXCLUSIVE)
      expect(last_response.status).to eq(200)
    end
  end

  # ===========================================================================
  # 3. UNLOCK with missing Lock-Token header → 400 Bad Request
  # ===========================================================================
  context "UNLOCK with missing Lock-Token header" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns 400 Bad Request" do
      unlock("/file.txt")
      expect(last_response.status).to eq(400)
    end
  end

  # ===========================================================================
  # 4. UNLOCK with token for a different path → 409 Conflict
  #    (with error body containing lock-token-matches-request-uri)
  # ===========================================================================
  context "UNLOCK with token belonging to a different path" do
    before do
      File.write(File.join(tmpdir, "file.txt"), "hello")
      File.write(File.join(tmpdir, "other.txt"), "world")
    end

    it "returns 409 Conflict" do
      other_token = acquire_lock("/other.txt")
      unlock("/file.txt", { "HTTP_LOCK_TOKEN" => "<#{other_token}>" })
      expect(last_response.status).to eq(409)
    end

    it "returns an XML error body with lock-token-matches-request-uri" do
      other_token = acquire_lock("/other.txt")
      unlock("/file.txt", { "HTTP_LOCK_TOKEN" => "<#{other_token}>" })
      doc = parse_xml(last_response.body)
      error_el = doc.at_xpath("//D:error/D:lock-token-matches-request-uri", dav_ns)
      expect(error_el).not_to be_nil
    end
  end

  # ===========================================================================
  # 5. UNLOCK with completely invalid/unknown token → 409 Conflict
  # ===========================================================================
  context "UNLOCK with completely unknown token" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns 409 Conflict" do
      unlock("/file.txt", { "HTTP_LOCK_TOKEN" => "<urn:uuid:00000000-0000-0000-0000-000000000000>" })
      expect(last_response.status).to eq(409)
    end
  end

  # ===========================================================================
  # 6. UNLOCK on a path that is not locked (but valid token format) → 409 Conflict
  # ===========================================================================
  context "UNLOCK on a path that is not locked" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns 409 Conflict" do
      unlock("/file.txt", { "HTTP_LOCK_TOKEN" => "<urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee>" })
      expect(last_response.status).to eq(409)
    end
  end
end
