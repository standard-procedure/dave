require "spec_helper"
require "rack/test"

RSpec.describe "OPTIONS" do
  include Rack::Test::Methods

  let(:tmpdir) { Dir.mktmpdir }
  let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
  let(:app) { Dave::Server.new(filesystem: filesystem) }

  after { FileUtils.rm_rf(tmpdir) }

  it "OPTIONS * returns 200" do
    options "*"
    expect(last_response.status).to eq(200)
  end

  it "OPTIONS * returns DAV: 1, 2 header" do
    options "*"
    expect(last_response.headers["DAV"]).to eq("1, 2")
  end

  it "OPTIONS * returns Allow header with all methods" do
    options "*"
    allow_header = last_response.headers["Allow"]
    expect(allow_header).not_to be_nil
    Dave::Server::ALLOWED_METHODS.each do |method|
      expect(allow_header).to include(method)
    end
  end

  it "OPTIONS /path returns same headers" do
    options "/some/path"
    expect(last_response.status).to eq(200)
    expect(last_response.headers["DAV"]).to eq("1, 2")
    allow_header = last_response.headers["Allow"]
    Dave::Server::ALLOWED_METHODS.each do |method|
      expect(allow_header).to include(method)
    end
  end

  it "returns a Date header" do
    options "/"
    expect(last_response.headers["Date"]).not_to be_nil
  end
end
