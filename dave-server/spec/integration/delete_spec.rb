require "spec_helper"
require "rack/test"

RSpec.describe "DELETE" do
  include Rack::Test::Methods

  let(:tmpdir) { Dir.mktmpdir }
  let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
  let(:app) { Dave::Server.new(filesystem: filesystem) }

  after { FileUtils.rm_rf(tmpdir) }

  LOCKINFO_EXCLUSIVE_DELETE = <<~XML.freeze
    <?xml version="1.0" encoding="UTF-8"?>
    <D:lockinfo xmlns:D="DAV:">
      <D:lockscope><D:exclusive/></D:lockscope>
      <D:locktype><D:write/></D:locktype>
    </D:lockinfo>
  XML

  def lock_token_for(path)
    env = { "rack.input" => StringIO.new(LOCKINFO_EXCLUSIVE_DELETE) }
    custom_request("LOCK", path, {}, env)
    last_response.headers["Lock-Token"].match(/<(urn:uuid:[^>]+)>/)[1]
  end

  it "DELETE /file returns 204 and removes the file" do
    File.write(File.join(tmpdir, "todelete.txt"), "content")
    delete "/todelete.txt"
    expect(last_response.status).to eq(204)
    expect(File.exist?(File.join(tmpdir, "todelete.txt"))).to be false
  end

  it "DELETE /collection/ recursively deletes and returns 204" do
    dir = File.join(tmpdir, "mydir")
    Dir.mkdir(dir)
    File.write(File.join(dir, "child.txt"), "child content")
    delete "/mydir"
    expect(last_response.status).to eq(204)
    expect(File.exist?(dir)).to be false
  end

  it "DELETE /nonexistent returns 404" do
    delete "/nonexistent.txt"
    expect(last_response.status).to eq(404)
  end

  it "DELETE with partial failure returns 207 with XML body" do
    # Use a mock filesystem that returns failed paths
    failing_fs = instance_double(Dave::FileSystemProvider)
    dir_resource = Dave::Resource.new(
      path: "/mydir/",
      collection: true,
      content_type: nil,
      content_length: nil,
      etag: '"abc"',
      last_modified: Time.now,
      created_at: Time.now
    )
    allow(failing_fs).to receive(:get_resource).with("/mydir/").and_return(dir_resource)
    allow(failing_fs).to receive(:delete).with("/mydir/").and_return(["/mydir/locked-file.txt"])

    partial_app = Dave::Server.new(filesystem: failing_fs)
    partial_rack = Rack::MockRequest.new(partial_app)

    response = partial_rack.delete("/mydir/")
    expect(response.status).to eq(207)
    expect(response.headers["Content-Type"]).to include("xml")
    expect(response.body).to include("locked-file.txt")
    expect(response.body).to include("500")
  end

  context "lock enforcement" do
    before { File.write(File.join(tmpdir, "locked.txt"), "content") }

    it "DELETE of locked resource without If header returns 423 Locked" do
      lock_token_for("/locked.txt")
      delete "/locked.txt"
      expect(last_response.status).to eq(423)
    end

    it "DELETE of locked resource with correct token in If header returns 204" do
      token = lock_token_for("/locked.txt")
      custom_request("DELETE", "/locked.txt", {}, { "HTTP_IF" => "(<#{token}>)" })
      expect(last_response.status).to eq(204)
    end
  end
end
