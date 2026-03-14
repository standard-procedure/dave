require "spec_helper"
require "rack/test"

RSpec.describe "PUT" do
  include Rack::Test::Methods

  let(:tmpdir) { Dir.mktmpdir }
  let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
  let(:app) { Dave::Server.new(filesystem: filesystem) }

  after { FileUtils.rm_rf(tmpdir) }

  LOCKINFO_EXCLUSIVE_PUT = <<~XML.freeze
    <?xml version="1.0" encoding="UTF-8"?>
    <D:lockinfo xmlns:D="DAV:">
      <D:lockscope><D:exclusive/></D:lockscope>
      <D:locktype><D:write/></D:locktype>
    </D:lockinfo>
  XML

  def lock_token_for(path)
    env = { "rack.input" => StringIO.new(LOCKINFO_EXCLUSIVE_PUT) }
    custom_request("LOCK", path, {}, env)
    last_response.headers["Lock-Token"].match(/<(urn:uuid:[^>]+)>/)[1]
  end

  it "PUT /newfile returns 201 with ETag header" do
    put "/newfile.txt", "new content", { "CONTENT_TYPE" => "text/plain" }
    expect(last_response.status).to eq(201)
    expect(last_response.headers["ETag"]).not_to be_nil
  end

  it "PUT /existing returns 204 (no ETag in response)" do
    File.write(File.join(tmpdir, "existing.txt"), "original")
    put "/existing.txt", "updated content", { "CONTENT_TYPE" => "text/plain" }
    expect(last_response.status).to eq(204)
  end

  it "PUT /missing-parent/file returns 409 Conflict" do
    put "/missing-parent/file.txt", "content", { "CONTENT_TYPE" => "text/plain" }
    expect(last_response.status).to eq(409)
  end

  it "PUT /collection (existing collection) returns 405 Method Not Allowed" do
    Dir.mkdir(File.join(tmpdir, "mydir"))
    put "/mydir", "content", { "CONTENT_TYPE" => "text/plain" }
    expect(last_response.status).to eq(405)
  end

  context "lock enforcement" do
    before { File.write(File.join(tmpdir, "locked.txt"), "original") }

    it "PUT to locked resource without If header returns 423 Locked" do
      lock_token_for("/locked.txt")
      put "/locked.txt", "new content", { "CONTENT_TYPE" => "text/plain" }
      expect(last_response.status).to eq(423)
    end

    it "PUT to locked resource with correct token in If header returns 204" do
      token = lock_token_for("/locked.txt")
      put "/locked.txt", "new content", {
        "CONTENT_TYPE" => "text/plain",
        "HTTP_IF"      => "(<#{token}>)"
      }
      expect(last_response.status).to eq(204)
    end
  end
end
