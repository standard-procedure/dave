require "spec_helper"
require "rack/test"

RSpec.describe "GET and HEAD" do
  include Rack::Test::Methods

  let(:tmpdir) { Dir.mktmpdir }
  let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
  let(:app) { Dave::Server.new(filesystem: filesystem) }

  after { FileUtils.rm_rf(tmpdir) }

  context "GET" do
    it "returns 200 with correct headers for an existing file" do
      File.write(File.join(tmpdir, "hello.txt"), "hello world")
      get "/hello.txt"
      expect(last_response.status).to eq(200)
      expect(last_response.headers["Content-Type"]).to eq("text/plain")
      expect(last_response.headers["Content-Length"]).to eq("11")
      expect(last_response.headers["ETag"]).not_to be_nil
      expect(last_response.headers["Last-Modified"]).not_to be_nil
      expect(last_response.body).to eq("hello world")
    end

    it "returns 404 for a nonexistent resource" do
      get "/nonexistent.txt"
      expect(last_response.status).to eq(404)
    end

    it "returns 200 for a collection (directory)" do
      Dir.mkdir(File.join(tmpdir, "mydir"))
      get "/mydir"
      expect(last_response.status).to eq(200)
    end

    it "returns 304 when If-None-Match matches ETag" do
      File.write(File.join(tmpdir, "hello.txt"), "hello world")
      get "/hello.txt"
      etag = last_response.headers["ETag"]

      get "/hello.txt", {}, { "HTTP_IF_NONE_MATCH" => etag }
      expect(last_response.status).to eq(304)
    end

    it "returns 200 when If-None-Match does not match ETag" do
      File.write(File.join(tmpdir, "hello.txt"), "hello world")
      get "/hello.txt", {}, { "HTTP_IF_NONE_MATCH" => '"does-not-match"' }
      expect(last_response.status).to eq(200)
    end

    it "returns a Date header on all responses" do
      get "/nonexistent"
      expect(last_response.status).to eq(404)
      expect(last_response.headers["Date"]).not_to be_nil
    end
  end

  describe "path handling" do
    it "decodes percent-encoded paths" do
      path = File.join(tmpdir, "hello world.txt")
      File.write(path, "content")

      get "/hello%20world.txt"
      expect(last_response.status).to eq(200)
    end

    it "treats /dir and /dir/ as the same collection" do
      Dir.mkdir(File.join(tmpdir, "mydir"))

      get "/mydir"
      expect(last_response.status).to eq(200)

      get "/mydir/"
      expect(last_response.status).to eq(200)
    end
  end

  context "HEAD" do
    it "returns same headers as GET but no body" do
      File.write(File.join(tmpdir, "hello.txt"), "hello world")
      # Use MockRequest directly: Rack::Test rewrites Content-Length to 0 for HEAD
      mock = Rack::MockRequest.new(app)
      response = mock.head("/hello.txt")
      expect(response.status).to eq(200)
      expect(response.headers["Content-Type"]).to eq("text/plain")
      expect(response.headers["Content-Length"]).to eq("11")
      expect(response.headers["ETag"]).not_to be_nil
      expect(response.headers["Last-Modified"]).not_to be_nil
      expect(response.body).to be_empty
    end

    it "returns 404 for a nonexistent resource" do
      head "/nonexistent.txt"
      expect(last_response.status).to eq(404)
    end
  end
end
