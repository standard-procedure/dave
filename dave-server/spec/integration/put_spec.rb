require "spec_helper"
require "rack/test"

RSpec.describe "PUT" do
  include Rack::Test::Methods

  let(:tmpdir) { Dir.mktmpdir }
  let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
  let(:app) { Dave::Server.new(filesystem: filesystem) }

  after { FileUtils.rm_rf(tmpdir) }

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
end
