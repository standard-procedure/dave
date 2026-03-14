require "spec_helper"
require "rack/test"
require "nokogiri"

RSpec.describe "PROPFIND" do
  include Rack::Test::Methods

  let(:tmpdir)     { Dir.mktmpdir }
  let(:filesystem) { Dave::FileSystemProvider.new(root: tmpdir) }
  let(:app)        { Dave::Server.new(filesystem: filesystem) }

  after { FileUtils.rm_rf(tmpdir) }

  # Helper: issue a PROPFIND request with optional body and headers
  def propfind(path, body: nil, headers: {})
    rack_env = { "rack.input" => StringIO.new(body.to_s) }.merge(headers)
    custom_request("PROPFIND", path, {}, rack_env)
  end

  # Helper: parse multi-status XML body
  def parse_xml(body)
    Nokogiri::XML(body)
  end

  def dav_ns
    { "D" => "DAV:" }
  end

  ALLPROP_BODY = <<~XML.freeze
    <?xml version="1.0" encoding="UTF-8"?>
    <D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>
  XML

  PROPNAME_BODY = <<~XML.freeze
    <?xml version="1.0" encoding="UTF-8"?>
    <D:propfind xmlns:D="DAV:"><D:propname/></D:propfind>
  XML

  def prop_body(*clark_names)
    props = clark_names.map do |cn|
      ns, local = cn.match(/\A\{([^}]+)\}(.+)\z/)[1..2]
      %(<D:#{local} xmlns:D="#{ns}"/>)
    end.join("\n    ")
    <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <D:propfind xmlns:D="DAV:">
        <D:prop>
          #{props}
        </D:prop>
      </D:propfind>
    XML
  end

  # =========================================================================
  # 1. PROPFIND on a file with Depth: 0 returns 207 with live properties
  # =========================================================================
  context "Depth: 0 on a file" do
    before { File.write(File.join(tmpdir, "readme.txt"), "hello") }

    it "returns 207 Multi-Status" do
      propfind("/readme.txt", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      expect(last_response.status).to eq(207)
    end

    it "returns application/xml content-type" do
      propfind("/readme.txt", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      expect(last_response.headers["Content-Type"]).to match(%r{application/xml})
    end

    it "includes the resource href in the response" do
      propfind("/readme.txt", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      hrefs = doc.xpath("//D:response/D:href", dav_ns).map(&:text)
      expect(hrefs).to include("/readme.txt")
    end

    it "includes displayname in allprop response" do
      propfind("/readme.txt", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      displayname = doc.at_xpath("//D:prop/D:displayname", dav_ns)&.text
      expect(displayname).to eq("readme.txt")
    end

    it "includes getetag in allprop response" do
      propfind("/readme.txt", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      etag = doc.at_xpath("//D:prop/D:getetag", dav_ns)
      expect(etag).not_to be_nil
    end

    it "includes getlastmodified in allprop response" do
      propfind("/readme.txt", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      lm = doc.at_xpath("//D:prop/D:getlastmodified", dav_ns)
      expect(lm).not_to be_nil
    end

    it "includes 200 status in propstat" do
      propfind("/readme.txt", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      status = doc.at_xpath("//D:propstat/D:status", dav_ns)&.text
      expect(status).to match(/200/)
    end
  end

  # =========================================================================
  # 2. allprop returns all live properties for a file
  # =========================================================================
  context "allprop" do
    before { File.write(File.join(tmpdir, "doc.txt"), "content here") }

    it "returns getcontentlength for a file" do
      propfind("/doc.txt", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      len = doc.at_xpath("//D:prop/D:getcontentlength", dav_ns)&.text
      expect(len).to eq("12")
    end

    it "returns getcontenttype for a file" do
      propfind("/doc.txt", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      ct = doc.at_xpath("//D:prop/D:getcontenttype", dav_ns)
      expect(ct).not_to be_nil
    end

    it "returns creationdate for a file" do
      propfind("/doc.txt", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      cd = doc.at_xpath("//D:prop/D:creationdate", dav_ns)
      expect(cd).not_to be_nil
    end

    it "returns resourcetype as empty for a regular file" do
      propfind("/doc.txt", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      rt = doc.at_xpath("//D:prop/D:resourcetype", dav_ns)
      expect(rt).not_to be_nil
      expect(rt.children.select(&:element?)).to be_empty
    end
  end

  # =========================================================================
  # 3. propname returns property names without values
  # =========================================================================
  context "propname" do
    before { File.write(File.join(tmpdir, "file.txt"), "test") }

    it "returns 207" do
      propfind("/file.txt", body: PROPNAME_BODY, headers: { "HTTP_DEPTH" => "0" })
      expect(last_response.status).to eq(207)
    end

    it "includes displayname element with no content" do
      propfind("/file.txt", body: PROPNAME_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      dn = doc.at_xpath("//D:prop/D:displayname", dav_ns)
      expect(dn).not_to be_nil
      expect(dn.text).to be_empty
    end

    it "includes getetag element with no content" do
      propfind("/file.txt", body: PROPNAME_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      etag = doc.at_xpath("//D:prop/D:getetag", dav_ns)
      expect(etag).not_to be_nil
      expect(etag.text).to be_empty
    end

    it "includes resourcetype element with no content" do
      propfind("/file.txt", body: PROPNAME_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      rt = doc.at_xpath("//D:prop/D:resourcetype", dav_ns)
      expect(rt).not_to be_nil
      expect(rt.children.select(&:element?)).to be_empty
    end
  end

  # =========================================================================
  # 4. Named prop request for {DAV:}displayname returns just that property
  # =========================================================================
  context "named prop — found property" do
    before { File.write(File.join(tmpdir, "named.txt"), "data") }

    it "returns 207" do
      propfind("/named.txt", body: prop_body("{DAV:}displayname"), headers: { "HTTP_DEPTH" => "0" })
      expect(last_response.status).to eq(207)
    end

    it "returns displayname value" do
      propfind("/named.txt", body: prop_body("{DAV:}displayname"), headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      dn = doc.at_xpath("//D:prop/D:displayname", dav_ns)&.text
      expect(dn).to eq("named.txt")
    end

    it "returns 200 propstat status" do
      propfind("/named.txt", body: prop_body("{DAV:}displayname"), headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      status = doc.at_xpath("//D:propstat/D:status", dav_ns)&.text
      expect(status).to match(/200/)
    end

    it "does not include unrequested properties" do
      propfind("/named.txt", body: prop_body("{DAV:}displayname"), headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      # getetag should not appear
      etag = doc.at_xpath("//D:prop/D:getetag", dav_ns)
      expect(etag).to be_nil
    end
  end

  # =========================================================================
  # 5. Named prop request for non-existent property returns 404 in propstat
  # =========================================================================
  context "named prop — missing property" do
    before { File.write(File.join(tmpdir, "missing.txt"), "data") }

    it "returns 207" do
      propfind("/missing.txt", body: prop_body("{DAV:}no-such-prop"), headers: { "HTTP_DEPTH" => "0" })
      expect(last_response.status).to eq(207)
    end

    it "returns 404 propstat for non-existent property" do
      propfind("/missing.txt", body: prop_body("{DAV:}no-such-prop"), headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      status_nodes = doc.xpath("//D:propstat/D:status", dav_ns).map(&:text)
      expect(status_nodes.any? { |s| s.match?(/404/) }).to be true
    end
  end

  # =========================================================================
  # 6. Named prop — one found + one not found → 200 propstat + 404 propstat
  # =========================================================================
  context "named prop — mixed found and missing" do
    before { File.write(File.join(tmpdir, "mixed.txt"), "data") }

    it "returns both 200 and 404 propstats" do
      body = prop_body("{DAV:}displayname", "{DAV:}no-such-prop")
      propfind("/mixed.txt", body: body, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      statuses = doc.xpath("//D:propstat/D:status", dav_ns).map(&:text)
      expect(statuses.any? { |s| s.match?(/200/) }).to be true
      expect(statuses.any? { |s| s.match?(/404/) }).to be true
    end

    it "puts displayname in the 200 propstat" do
      body = prop_body("{DAV:}displayname", "{DAV:}no-such-prop")
      propfind("/mixed.txt", body: body, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      ok_propstat = doc.xpath("//D:propstat", dav_ns).find { |ps| ps.at_xpath("D:status", dav_ns)&.text&.match?(/200/) }
      expect(ok_propstat&.at_xpath("D:prop/D:displayname", dav_ns)).not_to be_nil
    end

    it "puts missing prop in the 404 propstat" do
      body = prop_body("{DAV:}displayname", "{DAV:}no-such-prop")
      propfind("/mixed.txt", body: body, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      not_found_propstat = doc.xpath("//D:propstat", dav_ns).find { |ps| ps.at_xpath("D:status", dav_ns)&.text&.match?(/404/) }
      expect(not_found_propstat&.at_xpath("D:prop/D:no-such-prop", dav_ns)).not_to be_nil
    end
  end

  # =========================================================================
  # 7. PROPFIND on a collection with Depth: 0 — resourcetype is <D:collection/>
  # =========================================================================
  context "Depth: 0 on a collection" do
    before { Dir.mkdir(File.join(tmpdir, "mydir")) }

    it "returns 207" do
      propfind("/mydir", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      expect(last_response.status).to eq(207)
    end

    it "returns resourcetype containing <D:collection/>" do
      propfind("/mydir", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      collection_el = doc.at_xpath("//D:prop/D:resourcetype/D:collection", dav_ns)
      expect(collection_el).not_to be_nil
    end

    it "returns only the collection resource (not children) for Depth: 0" do
      File.write(File.join(tmpdir, "mydir", "child.txt"), "child")
      propfind("/mydir", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      hrefs = doc.xpath("//D:response/D:href", dav_ns).map(&:text)
      expect(hrefs.length).to eq(1)
    end
  end

  # =========================================================================
  # 8. PROPFIND on a collection with Depth: 1 — returns collection + children
  # =========================================================================
  context "Depth: 1 on a collection" do
    before do
      Dir.mkdir(File.join(tmpdir, "topdir"))
      File.write(File.join(tmpdir, "topdir", "child1.txt"), "a")
      File.write(File.join(tmpdir, "topdir", "child2.txt"), "b")
    end

    it "returns 207" do
      propfind("/topdir", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "1" })
      expect(last_response.status).to eq(207)
    end

    it "includes the collection itself and its children" do
      propfind("/topdir", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "1" })
      doc = parse_xml(last_response.body)
      hrefs = doc.xpath("//D:response/D:href", dav_ns).map(&:text)
      # Should have 3: the collection + 2 children
      expect(hrefs.length).to eq(3)
    end

    it "includes hrefs for child resources" do
      propfind("/topdir", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "1" })
      doc = parse_xml(last_response.body)
      hrefs = doc.xpath("//D:response/D:href", dav_ns).map(&:text)
      expect(hrefs).to include(match(%r{child1\.txt}))
      expect(hrefs).to include(match(%r{child2\.txt}))
    end

    it "does not recurse into subdirectories (only immediate children)" do
      Dir.mkdir(File.join(tmpdir, "topdir", "subdir"))
      File.write(File.join(tmpdir, "topdir", "subdir", "deep.txt"), "deep")
      propfind("/topdir", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "1" })
      doc = parse_xml(last_response.body)
      hrefs = doc.xpath("//D:response/D:href", dav_ns).map(&:text)
      # deep.txt should not appear
      expect(hrefs.none? { |h| h.include?("deep.txt") }).to be true
    end
  end

  # =========================================================================
  # 9. Depth: infinity returns 403 with propfind-finite-depth error
  # =========================================================================
  context "Depth: infinity" do
    before { File.write(File.join(tmpdir, "file.txt"), "data") }

    it "returns 403 Forbidden" do
      propfind("/file.txt", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "infinity" })
      expect(last_response.status).to eq(403)
    end

    it "returns propfind-finite-depth error XML" do
      propfind("/file.txt", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "infinity" })
      doc = parse_xml(last_response.body)
      error = doc.at_xpath("//D:error/D:propfind-finite-depth", dav_ns)
      expect(error).not_to be_nil
    end
  end

  # =========================================================================
  # 10. Missing Depth header → treats as infinity → 403
  # =========================================================================
  context "missing Depth header" do
    before { File.write(File.join(tmpdir, "file.txt"), "data") }

    it "returns 403 when Depth header is absent" do
      propfind("/file.txt", body: ALLPROP_BODY, headers: {})
      expect(last_response.status).to eq(403)
    end

    it "returns propfind-finite-depth error XML when Depth missing" do
      propfind("/file.txt", body: ALLPROP_BODY, headers: {})
      doc = parse_xml(last_response.body)
      error = doc.at_xpath("//D:error/D:propfind-finite-depth", dav_ns)
      expect(error).not_to be_nil
    end
  end

  # =========================================================================
  # 11. PROPFIND on non-existent resource → 404
  # =========================================================================
  context "non-existent resource" do
    it "returns 404" do
      propfind("/no-such-file.txt", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      expect(last_response.status).to eq(404)
    end
  end

  # =========================================================================
  # 12. Empty request body treated as allprop
  # =========================================================================
  context "empty body" do
    before { File.write(File.join(tmpdir, "empty-body.txt"), "content") }

    it "returns 207 for empty body (allprop implied)" do
      propfind("/empty-body.txt", body: "", headers: { "HTTP_DEPTH" => "0" })
      expect(last_response.status).to eq(207)
    end

    it "includes live properties like allprop when body is empty" do
      propfind("/empty-body.txt", body: "", headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      dn = doc.at_xpath("//D:prop/D:displayname", dav_ns)
      expect(dn).not_to be_nil
    end
  end

  # =========================================================================
  # 13. Dead properties included in allprop response
  # =========================================================================
  context "dead properties" do
    before do
      File.write(File.join(tmpdir, "dead.txt"), "content")
      filesystem.set_properties("/dead.txt", "{http://example.com/}author" => "Alice")
    end

    it "includes dead properties in allprop response" do
      propfind("/dead.txt", body: ALLPROP_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      # Find the author element in the example.com namespace
      author = doc.at_xpath("//*[local-name()='author' and namespace-uri()='http://example.com/']")
      expect(author).not_to be_nil
      expect(author.text).to eq("Alice")
    end

    it "includes dead properties in propname response (names only, empty values)" do
      propfind("/dead.txt", body: PROPNAME_BODY, headers: { "HTTP_DEPTH" => "0" })
      doc = parse_xml(last_response.body)
      author = doc.at_xpath("//*[local-name()='author' and namespace-uri()='http://example.com/']")
      expect(author).not_to be_nil
      expect(author.text).to be_empty
    end
  end

  # =========================================================================
  # 14. Malformed XML request body → 400
  # =========================================================================
  context "malformed XML" do
    before { File.write(File.join(tmpdir, "file.txt"), "data") }

    it "returns 400 Bad Request for malformed XML body" do
      propfind("/file.txt", body: "<not valid xml<<<", headers: { "HTTP_DEPTH" => "0" })
      expect(last_response.status).to eq(400)
    end
  end
end
