require "spec_helper"
require "dave/file_system_provider"
require "dave/security_configuration"
require "tmpdir"
require "fileutils"
require "rack/test"
require "nokogiri"
require "base64"

# Top-level constants to avoid conflicts with other integration specs
# (using unique prefixes) while remaining accessible inside RSpec describe blocks.
END_TO_END_ALLPROP_BODY = <<~XML.freeze
  <?xml version="1.0" encoding="UTF-8"?>
  <D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>
XML

END_TO_END_LOCKINFO_EXCLUSIVE = <<~XML.freeze
  <?xml version="1.0" encoding="UTF-8"?>
  <D:lockinfo xmlns:D="DAV:">
    <D:lockscope><D:exclusive/></D:lockscope>
    <D:locktype><D:write/></D:locktype>
  </D:lockinfo>
XML

END_TO_END_CUSTOM_NS = "http://example.com/ns/"

RSpec.describe "End-to-end integration" do
  include Rack::Test::Methods

  let(:tmpdir) { Dir.mktmpdir }
  after { FileUtils.rm_rf(tmpdir) }

  def parse_xml(body)
    Nokogiri::XML(body)
  end

  def dav_ns
    { "D" => "DAV:" }
  end

  # Issue a PROPFIND request
  def propfind(path, body:, headers: {})
    rack_env = { "rack.input" => StringIO.new(body.to_s) }.merge(headers)
    custom_request("PROPFIND", path, {}, rack_env)
  end

  # Issue a PROPPATCH request
  def proppatch(path, body:, headers: {})
    rack_env = { "rack.input" => StringIO.new(body.to_s) }.merge(headers)
    custom_request("PROPPATCH", path, {}, rack_env)
  end

  # Issue a LOCK request, return the last response
  def lock_resource(path, body:, headers: {})
    rack_env = { "rack.input" => StringIO.new(body.to_s) }.merge(headers)
    custom_request("LOCK", path, {}, rack_env)
    last_response
  end

  def extract_lock_token(response)
    response.headers["Lock-Token"].match(/<(urn:uuid:[^>]+)>/)[1]
  end

  # ===========================================================================
  # Scenario 1: Unauthenticated full workflow
  #   Full MKCOL → PUT → GET → PROPFIND → COPY → MOVE → DELETE cycle
  #   using only a FileSystemProvider (no security).
  # ===========================================================================
  describe "Scenario 1: unauthenticated full workflow" do
    let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
    let(:app) { Dave::Server.new(filesystem: filesystem) }

    it "runs the full MKCOL/PUT/GET/PROPFIND/COPY/MOVE/DELETE cycle" do
      # Step 1: MKCOL /testdir → 201
      custom_request("MKCOL", "/testdir", {}, { "rack.input" => StringIO.new("") })
      expect(last_response.status).to eq(201)

      # Step 2: PUT /testdir/hello.txt → 201
      put "/testdir/hello.txt", "Hello World", { "CONTENT_TYPE" => "text/plain" }
      expect(last_response.status).to eq(201)

      # Step 3: GET /testdir/hello.txt → 200, body "Hello World"
      get "/testdir/hello.txt"
      expect(last_response.status).to eq(200)
      expect(last_response.body).to eq("Hello World")

      # Step 4: PROPFIND /testdir with Depth:1 → 207, response includes hello.txt href
      propfind("/testdir", body: END_TO_END_ALLPROP_BODY, headers: { "HTTP_DEPTH" => "1" })
      expect(last_response.status).to eq(207)
      doc = parse_xml(last_response.body)
      hrefs = doc.xpath("//D:response/D:href", dav_ns).map(&:text)
      expect(hrefs.any? { |h| h.include?("hello.txt") }).to be true

      # Step 5: COPY /testdir/hello.txt to /testdir/hello2.txt → 201
      custom_request("COPY", "/testdir/hello.txt", {}, {
        "rack.input"       => StringIO.new(""),
        "HTTP_DESTINATION" => "http://example.org/testdir/hello2.txt"
      })
      expect(last_response.status).to eq(201)

      # Step 6: MOVE /testdir/hello2.txt to /testdir/world.txt → 201
      custom_request("MOVE", "/testdir/hello2.txt", {}, {
        "rack.input"       => StringIO.new(""),
        "HTTP_DESTINATION" => "http://example.org/testdir/world.txt"
      })
      expect(last_response.status).to eq(201)

      # Verify world.txt exists and hello2.txt does not
      get "/testdir/world.txt"
      expect(last_response.status).to eq(200)
      expect(last_response.body).to eq("Hello World")

      get "/testdir/hello2.txt"
      expect(last_response.status).to eq(404)

      # Step 7: DELETE /testdir → 204
      delete "/testdir"
      expect(last_response.status).to eq(204)

      # Verify testdir is gone
      get "/testdir/hello.txt"
      expect(last_response.status).to eq(404)
    end
  end

  # ===========================================================================
  # Scenario 2: Lock round-trip
  #   PUT → LOCK → PUT without token (423) → PUT with token (204)
  #   → UNLOCK → PUT (204, no longer locked)
  # ===========================================================================
  describe "Scenario 2: lock round-trip" do
    let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
    let(:app) { Dave::Server.new(filesystem: filesystem) }

    it "enforces lock/unlock lifecycle on a resource" do
      # Step 1: PUT /locked.txt → 201
      put "/locked.txt", "original content", { "CONTENT_TYPE" => "text/plain" }
      expect(last_response.status).to eq(201)

      # Step 2: LOCK /locked.txt → 200, extract Lock-Token
      lock_response = lock_resource("/locked.txt", body: END_TO_END_LOCKINFO_EXCLUSIVE)
      expect(lock_response.status).to eq(200)
      expect(lock_response.headers["Lock-Token"]).to match(/<urn:uuid:[^>]+>/)
      token = extract_lock_token(lock_response)
      expect(token).to match(/\Aurn:uuid:/)

      # Step 3: PUT /locked.txt without If header → 423 Locked
      put "/locked.txt", "overwrite attempt", { "CONTENT_TYPE" => "text/plain" }
      expect(last_response.status).to eq(423)

      # Step 4: PUT /locked.txt with correct If header → 204
      put "/locked.txt", "authorized overwrite", {
        "CONTENT_TYPE" => "text/plain",
        "HTTP_IF"      => "(<#{token}>)"
      }
      expect(last_response.status).to eq(204)

      # Verify content was updated
      get "/locked.txt"
      expect(last_response.status).to eq(200)
      expect(last_response.body).to eq("authorized overwrite")

      # Step 5: UNLOCK /locked.txt with Lock-Token header → 204
      custom_request("UNLOCK", "/locked.txt", {}, {
        "rack.input"      => StringIO.new(""),
        "HTTP_LOCK_TOKEN" => "<#{token}>"
      })
      expect(last_response.status).to eq(204)

      # Step 6: PUT /locked.txt → 204 (lock gone, write freely)
      put "/locked.txt", "free write after unlock", { "CONTENT_TYPE" => "text/plain" }
      expect(last_response.status).to eq(204)

      get "/locked.txt"
      expect(last_response.status).to eq(200)
      expect(last_response.body).to eq("free write after unlock")
    end
  end

  # ===========================================================================
  # Scenario 3: Property round-trip
  #   PUT → PROPPATCH (set) → PROPFIND (verify) → COPY → PROPFIND copy
  #   → PROPPATCH (remove one) → PROPFIND (verify partial removal)
  # ===========================================================================
  describe "Scenario 3: property round-trip" do
    let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
    let(:app) { Dave::Server.new(filesystem: filesystem) }

    def set_props_body(pairs)
      props = pairs.map do |name, value|
        %(<ns0:#{name} xmlns:ns0="#{END_TO_END_CUSTOM_NS}">#{value}</ns0:#{name}>)
      end.join("\n      ")
      <<~XML
        <?xml version="1.0" encoding="UTF-8"?>
        <D:propertyupdate xmlns:D="DAV:">
          <D:set>
            <D:prop>
              #{props}
            </D:prop>
          </D:set>
        </D:propertyupdate>
      XML
    end

    def remove_props_body(*names)
      props = names.map do |name|
        %(<ns0:#{name} xmlns:ns0="#{END_TO_END_CUSTOM_NS}"/>)
      end.join("\n      ")
      <<~XML
        <?xml version="1.0" encoding="UTF-8"?>
        <D:propertyupdate xmlns:D="DAV:">
          <D:remove>
            <D:prop>
              #{props}
            </D:prop>
          </D:remove>
        </D:propertyupdate>
      XML
    end

    it "sets, copies, and removes dead properties" do
      # Step 1: PUT /props.txt → 201
      put "/props.txt", "content", { "CONTENT_TYPE" => "text/plain" }
      expect(last_response.status).to eq(201)

      # Step 2: PROPPATCH — set author="Alice" and category="docs" → 207
      proppatch("/props.txt", body: set_props_body([["author", "Alice"], ["category", "docs"]]))
      expect(last_response.status).to eq(207)
      doc = parse_xml(last_response.body)
      statuses = doc.xpath("//D:propstat/D:status", dav_ns).map(&:text)
      expect(statuses.any? { |s| s.match?(/200/) }).to be true

      # Step 3: PROPFIND /props.txt Depth:0 allprop → 207, verify author and category present
      propfind("/props.txt", body: END_TO_END_ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      expect(last_response.status).to eq(207)
      doc = parse_xml(last_response.body)
      author_el = doc.at_xpath("//*[local-name()='author' and namespace-uri()='#{END_TO_END_CUSTOM_NS}']")
      category_el = doc.at_xpath("//*[local-name()='category' and namespace-uri()='#{END_TO_END_CUSTOM_NS}']")
      expect(author_el).not_to be_nil
      expect(author_el.text).to eq("Alice")
      expect(category_el).not_to be_nil
      expect(category_el.text).to eq("docs")

      # Step 4: COPY /props.txt to /props2.txt → 201
      custom_request("COPY", "/props.txt", {}, {
        "rack.input"       => StringIO.new(""),
        "HTTP_DESTINATION" => "http://example.org/props2.txt"
      })
      expect(last_response.status).to eq(201)

      # Step 5: PROPFIND /props2.txt Depth:0 allprop → 207, verify dead properties were copied
      propfind("/props2.txt", body: END_TO_END_ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      expect(last_response.status).to eq(207)
      doc = parse_xml(last_response.body)
      author_el2 = doc.at_xpath("//*[local-name()='author' and namespace-uri()='#{END_TO_END_CUSTOM_NS}']")
      category_el2 = doc.at_xpath("//*[local-name()='category' and namespace-uri()='#{END_TO_END_CUSTOM_NS}']")
      expect(author_el2).not_to be_nil
      expect(author_el2.text).to eq("Alice")
      expect(category_el2).not_to be_nil
      expect(category_el2.text).to eq("docs")

      # Step 6: PROPPATCH /props2.txt — remove author → 207
      proppatch("/props2.txt", body: remove_props_body("author"))
      expect(last_response.status).to eq(207)

      # Step 7: PROPFIND /props2.txt Depth:0 allprop → 207, author gone, category still present
      propfind("/props2.txt", body: END_TO_END_ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      expect(last_response.status).to eq(207)
      doc = parse_xml(last_response.body)
      author_el3 = doc.at_xpath("//*[local-name()='author' and namespace-uri()='#{END_TO_END_CUSTOM_NS}']")
      category_el3 = doc.at_xpath("//*[local-name()='category' and namespace-uri()='#{END_TO_END_CUSTOM_NS}']")
      expect(author_el3).to be_nil
      expect(category_el3).not_to be_nil
      expect(category_el3.text).to eq("docs")
    end
  end

  # ===========================================================================
  # Scenario 4: Authenticated workflow
  #   Uses Dave::SecurityConfiguration with alice (read_write on /) and
  #   bob (read on /shared/ only).
  # ===========================================================================
  describe "Scenario 4: authenticated workflow" do
    let(:alice_hash) { BCrypt::Password.create("alicepass", cost: BCrypt::Engine::MIN_COST) }
    let(:bob_hash)   { BCrypt::Password.create("bobpass",   cost: BCrypt::Engine::MIN_COST) }

    let(:security_config_yaml) do
      <<~YAML
        realm: "Dave WebDAV"
        users:
          alice:
            password: "#{alice_hash}"
            display_name: "Alice"
            access:
              - path: "/"
                permission: read_write
          bob:
            password: "#{bob_hash}"
            display_name: "Bob"
            access:
              - path: "/shared/"
                permission: read
      YAML
    end

    let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
    let(:security)   { Dave::SecurityConfiguration.new(security_config_yaml) }
    let(:app)        { Dave::Server.new(filesystem: filesystem, security: security) }

    def basic_auth(username, password)
      encoded = Base64.strict_encode64("#{username}:#{password}")
      { "HTTP_AUTHORIZATION" => "Basic #{encoded}" }
    end

    it "enforces authentication and path-based authorisation" do
      # Step 1: GET /any.txt without auth → 401
      get "/any.txt"
      expect(last_response.status).to eq(401)
      expect(last_response.headers["WWW-Authenticate"]).to match(/Basic realm=/)

      # Step 2: GET /any.txt with wrong password → 401
      get "/any.txt", {}, basic_auth("alice", "wrongpass")
      expect(last_response.status).to eq(401)

      # Step 3: PUT /hello.txt with alice credentials → 201
      put "/hello.txt", "hello from alice", basic_auth("alice", "alicepass").merge("CONTENT_TYPE" => "text/plain")
      expect(last_response.status).to eq(201)

      # Step 4: GET /hello.txt with alice credentials → 200
      get "/hello.txt", {}, basic_auth("alice", "alicepass")
      expect(last_response.status).to eq(200)
      expect(last_response.body).to eq("hello from alice")

      # Step 5: MKCOL /shared as alice → 201
      custom_request("MKCOL", "/shared", {}, {
        "rack.input" => StringIO.new("")
      }.merge(basic_auth("alice", "alicepass")))
      expect(last_response.status).to eq(201)

      # Step 6: PUT /shared/file.txt as alice → 201
      put "/shared/file.txt", "shared content", basic_auth("alice", "alicepass").merge("CONTENT_TYPE" => "text/plain")
      expect(last_response.status).to eq(201)

      # Step 7: GET /shared/file.txt with bob credentials → 200 (bob can read /shared/)
      get "/shared/file.txt", {}, basic_auth("bob", "bobpass")
      expect(last_response.status).to eq(200)
      expect(last_response.body).to eq("shared content")

      # Step 8: PUT /shared/newfile.txt with bob credentials → 403 (bob can only read /shared/)
      put "/shared/newfile.txt", "bob write attempt", basic_auth("bob", "bobpass").merge("CONTENT_TYPE" => "text/plain")
      expect(last_response.status).to eq(403)

      # Step 9: GET /hello.txt with bob credentials → 403 (bob has no access to /)
      get "/hello.txt", {}, basic_auth("bob", "bobpass")
      expect(last_response.status).to eq(403)
    end
  end
end
