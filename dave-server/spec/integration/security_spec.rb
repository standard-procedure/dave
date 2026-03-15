require "spec_helper"
require "rack/test"
require "base64"

RSpec.describe "Security (HTTP Basic Auth)" do
  include Rack::Test::Methods

  let(:tmpdir) { Dir.mktmpdir }
  let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }

  after { FileUtils.rm_rf(tmpdir) }

  # A simple in-memory security provider for testing
  let(:valid_principal) { Dave::Principal.new(id: "alice", display_name: "Alice") }

  let(:security_provider) do
    principal = valid_principal
    double("SecurityProvider").tap do |prov|
      allow(prov).to receive(:challenge).and_return('Basic realm="WebDAV"')
      allow(prov).to receive(:authenticate) do |credentials|
        if credentials[:username] == "alice" && credentials[:password] == "secret"
          principal
        else
          nil
        end
      end
      allow(prov).to receive(:authorize) do |_principal, path, _operation|
        path.start_with?("/allowed")
      end
    end
  end

  def basic_auth_header(username, password)
    encoded = Base64.strict_encode64("#{username}:#{password}")
    { "HTTP_AUTHORIZATION" => "Basic #{encoded}" }
  end

  context "with no security provider" do
    let(:app) { Dave::Server.new(filesystem: filesystem) }

    it "allows requests without Authorization header" do
      File.write(File.join(tmpdir, "hello.txt"), "hello")
      get "/hello.txt"
      expect(last_response.status).to eq(200)
    end

    it "allows requests with Authorization header (ignored)" do
      File.write(File.join(tmpdir, "hello.txt"), "hello")
      get "/hello.txt", {}, basic_auth_header("anyone", "anything")
      expect(last_response.status).to eq(200)
    end
  end

  context "with a security provider" do
    let(:app) { Dave::Server.new(filesystem: filesystem, security: security_provider) }

    before do
      File.write(File.join(tmpdir, "allowed.txt"), "allowed content")
      Dir.mkdir(File.join(tmpdir, "allowed_dir")) rescue nil
    end

    context "missing Authorization header" do
      it "returns 401" do
        get "/allowed.txt"
        expect(last_response.status).to eq(401)
      end

      it "includes WWW-Authenticate header" do
        get "/allowed.txt"
        expect(last_response.headers["WWW-Authenticate"]).to eq('Basic realm="WebDAV"')
      end
    end

    context "bad credentials" do
      it "returns 401 for wrong password" do
        get "/allowed.txt", {}, basic_auth_header("alice", "wrong")
        expect(last_response.status).to eq(401)
      end

      it "returns 401 for unknown user" do
        get "/allowed.txt", {}, basic_auth_header("bob", "secret")
        expect(last_response.status).to eq(401)
      end

      it "includes WWW-Authenticate header" do
        get "/allowed.txt", {}, basic_auth_header("alice", "wrong")
        expect(last_response.headers["WWW-Authenticate"]).to eq('Basic realm="WebDAV"')
      end
    end

    context "valid credentials but unauthorized path" do
      it "returns 403" do
        get "/forbidden.txt", {}, basic_auth_header("alice", "secret")
        expect(last_response.status).to eq(403)
      end
    end

    context "valid credentials and authorized path" do
      it "returns 200 for a read request (GET)" do
        get "/allowed.txt", {}, basic_auth_header("alice", "secret")
        expect(last_response.status).to eq(200)
      end

      it "returns 201 for a write request (PUT)" do
        put "/allowed_new.txt", "new content", basic_auth_header("alice", "secret")
        expect(last_response.status).to eq(201)
      end
    end

    context "operation mapping" do
      it "maps GET to :read operation" do
        expect(security_provider).to receive(:authorize).with(valid_principal, "/allowed.txt", :read).and_return(true)
        get "/allowed.txt", {}, basic_auth_header("alice", "secret")
      end

      it "maps HEAD to :read operation" do
        expect(security_provider).to receive(:authorize).with(valid_principal, "/allowed.txt", :read).and_return(true)
        mock = Rack::MockRequest.new(app)
        mock.request("HEAD", "/allowed.txt", basic_auth_header("alice", "secret"))
      end

      it "maps OPTIONS to :read operation" do
        expect(security_provider).to receive(:authorize).with(valid_principal, "/allowed.txt", :read).and_return(true)
        options "/allowed.txt", {}, basic_auth_header("alice", "secret")
      end

      it "maps PROPFIND to :read operation" do
        expect(security_provider).to receive(:authorize).with(valid_principal, "/allowed.txt", :read).and_return(true)
        rack_env = { "rack.input" => StringIO.new("") }.merge(basic_auth_header("alice", "secret")).merge("HTTP_DEPTH" => "0")
        custom_request("PROPFIND", "/allowed.txt", {}, rack_env)
      end

      it "maps PUT to :write operation" do
        expect(security_provider).to receive(:authorize).with(valid_principal, "/allowed_put.txt", :write).and_return(true)
        put "/allowed_put.txt", "content", basic_auth_header("alice", "secret")
      end

      it "maps DELETE to :write operation" do
        expect(security_provider).to receive(:authorize).with(valid_principal, "/allowed.txt", :write).and_return(true)
        delete "/allowed.txt", {}, basic_auth_header("alice", "secret")
      end

      it "maps MKCOL to :write operation" do
        expect(security_provider).to receive(:authorize).with(valid_principal, "/allowed_newdir", :write).and_return(true)
        rack_env = { "rack.input" => StringIO.new("") }.merge(basic_auth_header("alice", "secret"))
        custom_request("MKCOL", "/allowed_newdir", {}, rack_env)
      end

      it "maps LOCK to :write operation" do
        expect(security_provider).to receive(:authorize).with(valid_principal, "/allowed.txt", :write).and_return(true)
        body = <<~XML
          <?xml version="1.0" encoding="utf-8"?>
          <D:lockinfo xmlns:D="DAV:">
            <D:lockscope><D:exclusive/></D:lockscope>
            <D:locktype><D:write/></D:locktype>
            <D:owner><D:href>alice</D:href></D:owner>
          </D:lockinfo>
        XML
        rack_env = { "rack.input" => StringIO.new(body), "CONTENT_TYPE" => "application/xml" }.merge(basic_auth_header("alice", "secret"))
        custom_request("LOCK", "/allowed.txt", {}, rack_env)
      end

      it "maps UNLOCK to :write operation" do
        expect(security_provider).to receive(:authorize).with(valid_principal, "/allowed.txt", :write).and_return(true)
        rack_env = { "rack.input" => StringIO.new("") }.merge(basic_auth_header("alice", "secret")).merge("HTTP_LOCK_TOKEN" => "<urn:uuid:fake-token>")
        custom_request("UNLOCK", "/allowed.txt", {}, rack_env)
      end
    end
  end
end
