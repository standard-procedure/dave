require "spec_helper"
require "rack/test"

RSpec.describe "MKCOL" do
  let(:tmpdir) { Dir.mktmpdir }
  let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
  let(:app) { Dave::Server.new(filesystem: filesystem) }
  let(:mock) { Rack::MockRequest.new(app) }

  after { FileUtils.rm_rf(tmpdir) }

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
end
