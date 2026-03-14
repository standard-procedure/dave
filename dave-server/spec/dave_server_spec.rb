require "spec_helper"
require "rack/test"

RSpec.describe Dave::Server do
  include Rack::Test::Methods

  let(:tmpdir)     { Dir.mktmpdir }
  let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
  let(:app)        { Dave::Server.new(filesystem: filesystem) }

  after { FileUtils.rm_rf(tmpdir) }

  describe "unknown HTTP method" do
    it "returns 501 Not Implemented" do
      custom_request = Rack::MockRequest.new(app)
      response = custom_request.request("FOOBAR", "/")
      expect(response.status).to eq(501)
      expect(response.body).to include("Not Implemented")
    end
  end

  describe "top-level exception handling" do
    it "returns 500 when a handler raises an unexpected error" do
      broken_fs = instance_double(Dave::FileSystemProvider)
      allow(broken_fs).to receive(:get_resource).and_raise(RuntimeError, "boom")

      broken_app = Dave::Server.new(filesystem: broken_fs)
      request    = Rack::MockRequest.new(broken_app)
      response   = request.get("/anything")

      expect(response.status).to eq(500)
      expect(response.body).to include("boom")
    end
  end
end
