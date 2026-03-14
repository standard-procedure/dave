require "spec_helper"

RSpec.describe Dave::Properties do
  let(:file_resource) do
    Dave::Resource.new(
      path: "/documents/report.pdf",
      collection: false,
      content_type: "application/pdf",
      content_length: 1234,
      etag: '"abc123"',
      last_modified: Time.httpdate("Mon, 12 Jan 1998 09:25:56 GMT"),
      created_at: Time.utc(1997, 12, 1, 17, 42, 21)
    )
  end

  let(:collection_resource) do
    Dave::Resource.new(
      path: "/documents/",
      collection: true,
      content_type: nil,
      content_length: nil,
      etag: '"col456"',
      last_modified: Time.httpdate("Tue, 13 Jan 1998 10:00:00 GMT"),
      created_at: Time.utc(1997, 11, 15, 8, 0, 0)
    )
  end

  describe "LIVE_PROPS" do
    it "is a frozen array of Clark notation strings" do
      expect(Dave::Properties::LIVE_PROPS).to be_frozen
      expect(Dave::Properties::LIVE_PROPS).to all(match(/\A\{DAV:\}/))
    end

    it "contains all required live properties" do
      expected = %w[
        {DAV:}displayname
        {DAV:}getcontentlength
        {DAV:}getcontenttype
        {DAV:}getetag
        {DAV:}getlastmodified
        {DAV:}creationdate
        {DAV:}resourcetype
        {DAV:}supportedlock
        {DAV:}lockdiscovery
        {DAV:}getcontentlanguage
      ]
      expect(Dave::Properties::LIVE_PROPS).to include(*expected)
    end
  end

  describe ".live?" do
    it "returns true for known live property names" do
      expect(Dave::Properties.live?("{DAV:}displayname")).to be true
      expect(Dave::Properties.live?("{DAV:}getcontentlength")).to be true
      expect(Dave::Properties.live?("{DAV:}getcontenttype")).to be true
      expect(Dave::Properties.live?("{DAV:}getetag")).to be true
      expect(Dave::Properties.live?("{DAV:}getlastmodified")).to be true
      expect(Dave::Properties.live?("{DAV:}creationdate")).to be true
      expect(Dave::Properties.live?("{DAV:}resourcetype")).to be true
      expect(Dave::Properties.live?("{DAV:}supportedlock")).to be true
      expect(Dave::Properties.live?("{DAV:}lockdiscovery")).to be true
      expect(Dave::Properties.live?("{DAV:}getcontentlanguage")).to be true
    end

    it "returns false for unknown/dead property names" do
      expect(Dave::Properties.live?("{DAV:}author")).to be false
      expect(Dave::Properties.live?("{http://example.com/}custom")).to be false
      expect(Dave::Properties.live?("plain-name")).to be false
    end
  end

  describe ".live_property" do
    context "unknown clark name" do
      it "raises ArgumentError" do
        expect {
          Dave::Properties.live_property(file_resource, "{DAV:}unknown")
        }.to raise_error(ArgumentError, /not a live property/)
      end
    end

    context "{DAV:}displayname" do
      it "returns the last path segment for a file" do
        expect(Dave::Properties.live_property(file_resource, "{DAV:}displayname")).to eq("report.pdf")
      end

      it "returns the directory name for a collection" do
        expect(Dave::Properties.live_property(collection_resource, "{DAV:}displayname")).to eq("documents")
      end
    end

    context "{DAV:}getcontentlength" do
      it "returns the content length as a string for files" do
        expect(Dave::Properties.live_property(file_resource, "{DAV:}getcontentlength")).to eq("1234")
      end

      it "returns nil for collections" do
        expect(Dave::Properties.live_property(collection_resource, "{DAV:}getcontentlength")).to be_nil
      end
    end

    context "{DAV:}getcontenttype" do
      it "returns the content type for files" do
        expect(Dave::Properties.live_property(file_resource, "{DAV:}getcontenttype")).to eq("application/pdf")
      end

      it "returns nil for collections" do
        expect(Dave::Properties.live_property(collection_resource, "{DAV:}getcontenttype")).to be_nil
      end
    end

    context "{DAV:}getetag" do
      it "returns the etag for files" do
        expect(Dave::Properties.live_property(file_resource, "{DAV:}getetag")).to eq('"abc123"')
      end

      it "returns the etag for collections" do
        expect(Dave::Properties.live_property(collection_resource, "{DAV:}getetag")).to eq('"col456"')
      end
    end

    context "{DAV:}getlastmodified" do
      it "returns RFC 1123 date string for files" do
        result = Dave::Properties.live_property(file_resource, "{DAV:}getlastmodified")
        expect(result).to eq("Mon, 12 Jan 1998 09:25:56 GMT")
      end

      it "returns RFC 1123 date string for collections" do
        result = Dave::Properties.live_property(collection_resource, "{DAV:}getlastmodified")
        expect(result).to eq("Tue, 13 Jan 1998 10:00:00 GMT")
      end
    end

    context "{DAV:}creationdate" do
      it "returns ISO 8601 date string for files" do
        result = Dave::Properties.live_property(file_resource, "{DAV:}creationdate")
        expect(result).to eq("1997-12-01T17:42:21Z")
      end

      it "returns ISO 8601 date string for collections" do
        result = Dave::Properties.live_property(collection_resource, "{DAV:}creationdate")
        expect(result).to eq("1997-11-15T08:00:00Z")
      end
    end

    context "{DAV:}resourcetype" do
      it "returns empty string for non-collection resources" do
        expect(Dave::Properties.live_property(file_resource, "{DAV:}resourcetype")).to eq("")
      end

      it "returns collection XML fragment for collections" do
        result = Dave::Properties.live_property(collection_resource, "{DAV:}resourcetype")
        expect(result).to eq('<D:collection xmlns:D="DAV:"/>')
      end
    end

    context "{DAV:}supportedlock" do
      it "returns exclusive+shared write lock entries for files" do
        result = Dave::Properties.live_property(file_resource, "{DAV:}supportedlock")
        expect(result).to include("<D:lockentry")
        expect(result).to include("<D:exclusive/>")
        expect(result).to include("<D:shared/>")
        expect(result).to include("<D:write/>")
      end

      it "returns exclusive+shared write lock entries for collections" do
        result = Dave::Properties.live_property(collection_resource, "{DAV:}supportedlock")
        expect(result).to include("<D:lockentry")
        expect(result).to include("<D:exclusive/>")
        expect(result).to include("<D:shared/>")
        expect(result).to include("<D:write/>")
      end
    end

    context "{DAV:}lockdiscovery" do
      it "returns empty string when no lock_manager given" do
        expect(Dave::Properties.live_property(file_resource, "{DAV:}lockdiscovery")).to eq("")
      end

      it "returns empty string when lock_manager is nil" do
        expect(Dave::Properties.live_property(file_resource, "{DAV:}lockdiscovery", lock_manager: nil)).to eq("")
      end

      it "returns empty string when no locks exist for the resource" do
        lock_manager = Dave::LockManager.new
        result = Dave::Properties.live_property(file_resource, "{DAV:}lockdiscovery", lock_manager: lock_manager)
        expect(result).to eq("")
      end

      it "returns activelock XML when a lock exists for the resource" do
        lock_manager = Dave::LockManager.new
        lock_manager.acquire(file_resource.path, scope: :exclusive, depth: :infinity, timeout: 3600)
        result = Dave::Properties.live_property(file_resource, "{DAV:}lockdiscovery", lock_manager: lock_manager)
        expect(result).to include("<D:activelock")
        expect(result).to include("<D:exclusive/>")
        expect(result).to include("<D:write/>")
        expect(result).to include("Second-3600")
      end

      it "returns activelock XML with infinite timeout" do
        lock_manager = Dave::LockManager.new
        lock_manager.acquire(file_resource.path, scope: :shared, depth: :zero, timeout: :infinite)
        result = Dave::Properties.live_property(file_resource, "{DAV:}lockdiscovery", lock_manager: lock_manager)
        expect(result).to include("<D:activelock")
        expect(result).to include("<D:shared/>")
        expect(result).to include("Infinite")
      end

      it "returns activelock XML with owner when owner provided" do
        lock_manager = Dave::LockManager.new
        lock_manager.acquire(file_resource.path, scope: :exclusive, depth: :zero, owner: "<D:href>http://example.com/user</D:href>")
        result = Dave::Properties.live_property(file_resource, "{DAV:}lockdiscovery", lock_manager: lock_manager)
        expect(result).to include("<D:owner>")
        expect(result).to include("http://example.com/user")
      end

      it "returns empty string for collections with no locks" do
        lock_manager = Dave::LockManager.new
        result = Dave::Properties.live_property(collection_resource, "{DAV:}lockdiscovery", lock_manager: lock_manager)
        expect(result).to eq("")
      end
    end

    context "{DAV:}getcontentlanguage" do
      it "returns nil for files (not stored)" do
        expect(Dave::Properties.live_property(file_resource, "{DAV:}getcontentlanguage")).to be_nil
      end

      it "returns nil for collections" do
        expect(Dave::Properties.live_property(collection_resource, "{DAV:}getcontentlanguage")).to be_nil
      end
    end
  end

  describe ".live_properties" do
    context "for a non-collection resource" do
      subject(:props) { Dave::Properties.live_properties(file_resource) }

      it "returns a Hash" do
        expect(props).to be_a(Hash)
      end

      it "includes displayname" do
        expect(props["{DAV:}displayname"]).to eq("report.pdf")
      end

      it "includes getcontentlength" do
        expect(props["{DAV:}getcontentlength"]).to eq("1234")
      end

      it "includes getcontenttype" do
        expect(props["{DAV:}getcontenttype"]).to eq("application/pdf")
      end

      it "includes getetag" do
        expect(props["{DAV:}getetag"]).to eq('"abc123"')
      end

      it "includes getlastmodified" do
        expect(props["{DAV:}getlastmodified"]).to eq("Mon, 12 Jan 1998 09:25:56 GMT")
      end

      it "includes creationdate" do
        expect(props["{DAV:}creationdate"]).to eq("1997-12-01T17:42:21Z")
      end

      it "includes resourcetype as empty string" do
        expect(props["{DAV:}resourcetype"]).to eq("")
      end

      it "includes supportedlock with lock entry XML" do
        expect(props["{DAV:}supportedlock"]).to include("<D:lockentry")
      end

      it "includes lockdiscovery as empty string (no lock_manager)" do
        expect(props["{DAV:}lockdiscovery"]).to eq("")
      end

      it "does not include getcontentlanguage (nil property)" do
        expect(props.key?("{DAV:}getcontentlanguage")).to be false
      end
    end

    context "for a collection resource" do
      subject(:props) { Dave::Properties.live_properties(collection_resource) }

      it "includes resourcetype as collection XML" do
        expect(props["{DAV:}resourcetype"]).to eq('<D:collection xmlns:D="DAV:"/>')
      end

      it "does not include getcontentlength (nil for collections)" do
        expect(props.key?("{DAV:}getcontentlength")).to be false
      end

      it "does not include getcontenttype (nil for collections)" do
        expect(props.key?("{DAV:}getcontenttype")).to be false
      end

      it "does not include getcontentlanguage" do
        expect(props.key?("{DAV:}getcontentlanguage")).to be false
      end

      it "includes displayname as directory name without trailing slash" do
        expect(props["{DAV:}displayname"]).to eq("documents")
      end

      it "includes getetag" do
        expect(props["{DAV:}getetag"]).to eq('"col456"')
      end
    end
  end
end
