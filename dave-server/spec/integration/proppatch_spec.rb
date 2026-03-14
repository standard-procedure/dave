require "spec_helper"
require "rack/test"
require "nokogiri"

RSpec.describe "PROPPATCH" do
  include Rack::Test::Methods

  let(:tmpdir)     { Dir.mktmpdir }
  let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
  let(:app)        { Dave::Server.new(filesystem: filesystem) }

  after { FileUtils.rm_rf(tmpdir) }

  def proppatch(path, body:, headers: {})
    rack_env = { "rack.input" => StringIO.new(body.to_s) }.merge(headers)
    custom_request("PROPPATCH", path, {}, rack_env)
  end

  def parse_xml(body)
    Nokogiri::XML(body)
  end

  def dav_ns
    { "D" => "DAV:" }
  end

  def set_body(*prop_pairs)
    props = prop_pairs.map do |clark_name, value|
      ns, local = clark_name.match(/\A\{([^}]+)\}(.+)\z/)[1..2]
      %(<ns0:#{local} xmlns:ns0="#{ns}">#{value}</ns0:#{local}>)
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

  def remove_body(*clark_names)
    props = clark_names.map do |clark_name|
      ns, local = clark_name.match(/\A\{([^}]+)\}(.+)\z/)[1..2]
      %(<ns0:#{local} xmlns:ns0="#{ns}"/>)
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

  def set_and_remove_body(set_pairs, remove_names)
    set_props = set_pairs.map do |clark_name, value|
      ns, local = clark_name.match(/\A\{([^}]+)\}(.+)\z/)[1..2]
      %(<ns0:#{local} xmlns:ns0="#{ns}">#{value}</ns0:#{local}>)
    end.join("\n      ")
    remove_props = remove_names.map do |clark_name|
      ns, local = clark_name.match(/\A\{([^}]+)\}(.+)\z/)[1..2]
      %(<ns0:#{local} xmlns:ns0="#{ns}"/>)
    end.join("\n      ")
    <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <D:propertyupdate xmlns:D="DAV:">
        <D:set>
          <D:prop>
            #{set_props}
          </D:prop>
        </D:set>
        <D:remove>
          <D:prop>
            #{remove_props}
          </D:prop>
        </D:remove>
      </D:propertyupdate>
    XML
  end

  # =========================================================================
  # 1. PROPPATCH set a dead property on a file → 207 with 200 propstat
  # =========================================================================
  context "set a dead property on a file" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns 207 Multi-Status" do
      proppatch("/file.txt", body: set_body(["{http://example.com/}author", "Alice"]))
      expect(last_response.status).to eq(207)
    end

    it "returns application/xml content-type" do
      proppatch("/file.txt", body: set_body(["{http://example.com/}author", "Alice"]))
      expect(last_response.headers["Content-Type"]).to match(%r{application/xml})
    end

    it "includes a 200 propstat for the set property" do
      proppatch("/file.txt", body: set_body(["{http://example.com/}author", "Alice"]))
      doc = parse_xml(last_response.body)
      statuses = doc.xpath("//D:propstat/D:status", dav_ns).map(&:text)
      expect(statuses.any? { |s| s.match?(/200/) }).to be true
    end

    it "stores the property so it can be retrieved later" do
      proppatch("/file.txt", body: set_body(["{http://example.com/}author", "Alice"]))
      expect(filesystem.get_properties("/file.txt")["{http://example.com/}author"]).to eq("Alice")
    end

    it "includes the resource href in the response" do
      proppatch("/file.txt", body: set_body(["{http://example.com/}author", "Alice"]))
      doc = parse_xml(last_response.body)
      hrefs = doc.xpath("//D:response/D:href", dav_ns).map(&:text)
      expect(hrefs).to include("/file.txt")
    end
  end

  # =========================================================================
  # 2. PROPPATCH remove a dead property → 207 with 200 propstat, property gone
  # =========================================================================
  context "remove a dead property" do
    before do
      File.write(File.join(tmpdir, "file.txt"), "hello")
      filesystem.set_properties("/file.txt", "{http://example.com/}author" => "Alice")
    end

    it "returns 207 Multi-Status" do
      proppatch("/file.txt", body: remove_body("{http://example.com/}author"))
      expect(last_response.status).to eq(207)
    end

    it "includes a 200 propstat for the removed property" do
      proppatch("/file.txt", body: remove_body("{http://example.com/}author"))
      doc = parse_xml(last_response.body)
      statuses = doc.xpath("//D:propstat/D:status", dav_ns).map(&:text)
      expect(statuses.any? { |s| s.match?(/200/) }).to be true
    end

    it "removes the property from storage" do
      proppatch("/file.txt", body: remove_body("{http://example.com/}author"))
      expect(filesystem.get_properties("/file.txt")).not_to have_key("{http://example.com/}author")
    end
  end

  # =========================================================================
  # 3. PROPPATCH set + remove in same request → 207 with 200 propstat for all
  # =========================================================================
  context "set and remove in same request" do
    before do
      File.write(File.join(tmpdir, "file.txt"), "hello")
      filesystem.set_properties("/file.txt", "{http://example.com/}old" => "value")
    end

    it "returns 207 Multi-Status" do
      body = set_and_remove_body(
        [["{http://example.com/}new", "data"]],
        ["{http://example.com/}old"]
      )
      proppatch("/file.txt", body: body)
      expect(last_response.status).to eq(207)
    end

    it "returns a 200 propstat covering all operations" do
      body = set_and_remove_body(
        [["{http://example.com/}new", "data"]],
        ["{http://example.com/}old"]
      )
      proppatch("/file.txt", body: body)
      doc = parse_xml(last_response.body)
      statuses = doc.xpath("//D:propstat/D:status", dav_ns).map(&:text)
      expect(statuses.any? { |s| s.match?(/200/) }).to be true
      expect(statuses.none? { |s| s.match?(/4\d\d/) }).to be true
    end

    it "applies both set and remove operations" do
      body = set_and_remove_body(
        [["{http://example.com/}new", "data"]],
        ["{http://example.com/}old"]
      )
      proppatch("/file.txt", body: body)
      props = filesystem.get_properties("/file.txt")
      expect(props).to have_key("{http://example.com/}new")
      expect(props).not_to have_key("{http://example.com/}old")
    end
  end

  # =========================================================================
  # 4. PROPPATCH trying to set a live property → 207 with 403 propstat
  # =========================================================================
  context "trying to set a live property" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns 207 Multi-Status" do
      proppatch("/file.txt", body: set_body(["{DAV:}getetag", "custom-etag"]))
      expect(last_response.status).to eq(207)
    end

    it "returns 403 propstat for the live property" do
      proppatch("/file.txt", body: set_body(["{DAV:}getetag", "custom-etag"]))
      doc = parse_xml(last_response.body)
      statuses = doc.xpath("//D:propstat/D:status", dav_ns).map(&:text)
      expect(statuses.any? { |s| s.match?(/403/) }).to be true
    end

    it "does not return a 200 propstat" do
      proppatch("/file.txt", body: set_body(["{DAV:}getetag", "custom-etag"]))
      doc = parse_xml(last_response.body)
      statuses = doc.xpath("//D:propstat/D:status", dav_ns).map(&:text)
      expect(statuses.none? { |s| s.match?(/200/) }).to be true
    end
  end

  # =========================================================================
  # 5. Atomic: set live + set dead → live=403, dead=424 Failed Dependency
  # =========================================================================
  context "atomic failure: live + dead in same request" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    let(:body) do
      set_and_remove_body(
        [["{DAV:}getetag", "evil"], ["{http://example.com/}custom", "ok"]],
        []
      )
    end

    it "returns 207 Multi-Status" do
      proppatch("/file.txt", body: body)
      expect(last_response.status).to eq(207)
    end

    it "returns 403 for the live property" do
      proppatch("/file.txt", body: body)
      doc = parse_xml(last_response.body)
      forbidden_propstat = doc.xpath("//D:propstat", dav_ns).find do |ps|
        ps.at_xpath("D:status", dav_ns)&.text&.match?(/403/)
      end
      expect(forbidden_propstat).not_to be_nil
      expect(forbidden_propstat.at_xpath("D:prop/D:getetag", dav_ns)).not_to be_nil
    end

    it "returns 424 Failed Dependency for the dead property" do
      proppatch("/file.txt", body: body)
      doc = parse_xml(last_response.body)
      dep_propstat = doc.xpath("//D:propstat", dav_ns).find do |ps|
        ps.at_xpath("D:status", dav_ns)&.text&.match?(/424/)
      end
      expect(dep_propstat).not_to be_nil
    end

    it "does not store any properties when atomic failure occurs" do
      proppatch("/file.txt", body: body)
      props = filesystem.get_properties("/file.txt")
      expect(props).not_to have_key("{http://example.com/}custom")
    end
  end

  # =========================================================================
  # 6. PROPPATCH on non-existent resource → 404
  # =========================================================================
  context "non-existent resource" do
    it "returns 404" do
      proppatch("/no-such-file.txt", body: set_body(["{http://example.com/}author", "Alice"]))
      expect(last_response.status).to eq(404)
    end
  end

  # =========================================================================
  # 7. Malformed XML body → 400
  # =========================================================================
  context "malformed XML body" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns 400 Bad Request" do
      proppatch("/file.txt", body: "<not valid xml<<<")
      expect(last_response.status).to eq(400)
    end
  end

  # =========================================================================
  # 8. Missing/empty body → 400
  # =========================================================================
  context "missing or empty body" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns 400 for empty body" do
      proppatch("/file.txt", body: "")
      expect(last_response.status).to eq(400)
    end

    it "returns 400 for nil body" do
      proppatch("/file.txt", body: nil)
      expect(last_response.status).to eq(400)
    end
  end

  # =========================================================================
  # 9. Set a custom namespace property → 207 with 200
  # =========================================================================
  context "custom namespace property" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns 207 for a custom namespace property" do
      proppatch("/file.txt", body: set_body(["{http://myapp.example.com/ns/}category", "work"]))
      expect(last_response.status).to eq(207)
    end

    it "stores the custom namespace property" do
      proppatch("/file.txt", body: set_body(["{http://myapp.example.com/ns/}category", "work"]))
      props = filesystem.get_properties("/file.txt")
      expect(props["{http://myapp.example.com/ns/}category"]).to eq("work")
    end
  end

  # =========================================================================
  # lock enforcement
  # =========================================================================
  context "lock enforcement" do
    LOCKINFO_EXCLUSIVE_PROPPATCH = <<~XML.freeze
      <?xml version="1.0" encoding="UTF-8"?>
      <D:lockinfo xmlns:D="DAV:">
        <D:lockscope><D:exclusive/></D:lockscope>
        <D:locktype><D:write/></D:locktype>
      </D:lockinfo>
    XML

    before { File.write(File.join(tmpdir, "locked.txt"), "content") }

    def lock_token_for_proppatch(path)
      env = { "rack.input" => StringIO.new(LOCKINFO_EXCLUSIVE_PROPPATCH) }
      custom_request("LOCK", path, {}, env)
      last_response.headers["Lock-Token"].match(/<(urn:uuid:[^>]+)>/)[1]
    end

    it "PROPPATCH on locked resource without If header returns 423 Locked" do
      lock_token_for_proppatch("/locked.txt")
      proppatch("/locked.txt", body: set_body(["{http://example.com/}author", "Eve"]))
      expect(last_response.status).to eq(423)
    end

    it "PROPPATCH on locked resource with correct token in If header returns 207" do
      token = lock_token_for_proppatch("/locked.txt")
      proppatch("/locked.txt",
        body:    set_body(["{http://example.com/}author", "Eve"]),
        headers: { "HTTP_IF" => "(<#{token}>)" }
      )
      expect(last_response.status).to eq(207)
    end
  end

  # =========================================================================
  # 10. After successful PROPPATCH, PROPFIND allprop returns the new dead prop
  # =========================================================================
  context "PROPFIND allprop after PROPPATCH" do
    before { File.write(File.join(tmpdir, "file.txt"), "hello") }

    it "returns the newly set dead property in an allprop PROPFIND" do
      # First set the property via PROPPATCH
      proppatch("/file.txt", body: set_body(["{http://example.com/}author", "Bob"]))
      expect(last_response.status).to eq(207)

      # Now retrieve it with PROPFIND allprop
      allprop_body = <<~XML
        <?xml version="1.0" encoding="UTF-8"?>
        <D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>
      XML
      rack_env = { "rack.input" => StringIO.new(allprop_body), "HTTP_DEPTH" => "0" }
      custom_request("PROPFIND", "/file.txt", {}, rack_env)

      doc = parse_xml(last_response.body)
      author = doc.at_xpath("//*[local-name()='author' and namespace-uri()='http://example.com/']")
      expect(author).not_to be_nil
      expect(author.text).to eq("Bob")
    end
  end
end
