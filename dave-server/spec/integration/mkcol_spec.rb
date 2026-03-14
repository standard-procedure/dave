require "spec_helper"
require "rack/test"

RSpec.describe "MKCOL" do
  include Rack::Test::Methods

  let(:tmpdir) { Dir.mktmpdir }
  let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
  let(:app) { Dave::Server.new(filesystem: filesystem) }
  let(:mock) { Rack::MockRequest.new(app) }

  after { FileUtils.rm_rf(tmpdir) }

  LOCKINFO_EXCLUSIVE_MKCOL = <<~XML.freeze
    <?xml version="1.0" encoding="UTF-8"?>
    <D:lockinfo xmlns:D="DAV:">
      <D:lockscope><D:exclusive/></D:lockscope>
      <D:locktype><D:write/></D:locktype>
    </D:lockinfo>
  XML

  def lock_token_for(path)
    env = { "rack.input" => StringIO.new(LOCKINFO_EXCLUSIVE_MKCOL) }
    custom_request("LOCK", path, {}, env)
    last_response.headers["Lock-Token"].match(/<(urn:uuid:[^>]+)>/)[1]
  end

  it "MKCOL /newdir returns 201" do
    response = mock.request("MKCOL", "/newdir")
    expect(response.status).to eq(201)
    expect(File.directory?(File.join(tmpdir, "newdir"))).to be true
  end

  it "MKCOL /existing returns 405 when resource already exists" do
    Dir.mkdir(File.join(tmpdir, "existing"))
    response = mock.request("MKCOL", "/existing")
    expect(response.status).to eq(405)
  end

  it "MKCOL /missing-parent/newdir returns 409 when parent does not exist" do
    response = mock.request("MKCOL", "/missing-parent/newdir")
    expect(response.status).to eq(409)
  end

  it "MKCOL with a request body returns 415 Unsupported Media Type" do
    response = mock.request("MKCOL", "/newdir2",
      input: "some body content",
      "CONTENT_TYPE" => "text/plain"
    )
    expect(response.status).to eq(415)
  end

  context "lock enforcement" do
    before { Dir.mkdir(File.join(tmpdir, "lockeddir")) }

    it "MKCOL on locked path without If header returns 423 Locked" do
      lock_token_for("/lockeddir")
      custom_request("MKCOL", "/lockeddir/newchild", {}, {})
      expect(last_response.status).to eq(423)
    end

    it "MKCOL on locked path with correct token in If header returns 201" do
      token = lock_token_for("/lockeddir")
      custom_request("MKCOL", "/lockeddir/newchild", {}, { "HTTP_IF" => "(<#{token}>)" })
      expect(last_response.status).to eq(201)
    end
  end
end
