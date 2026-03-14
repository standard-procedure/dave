require "spec_helper"
require "tmpdir"
require "stringio"

RSpec.describe "Dave::FileSystemProvider dead property storage" do
  let(:tmpdir) { Dir.mktmpdir }
  subject(:provider) { Dave::FileSystemProvider.new(root: tmpdir) }

  after { FileUtils.rm_rf(tmpdir) }

  # ──────────────────────────────────────────────
  # get_properties
  # ──────────────────────────────────────────────

  describe "#get_properties" do
    context "when the resource exists but has no sidecar" do
      before { File.write(File.join(tmpdir, "file.txt"), "x") }

      it "returns an empty hash" do
        expect(provider.get_properties("/file.txt")).to eq({})
      end
    end

    context "when the sidecar file does not exist (missing path)" do
      it "returns an empty hash without raising" do
        expect(provider.get_properties("/nonexistent.txt")).to eq({})
      end
    end

    context "when the sidecar JSON is corrupt" do
      it "returns empty hash without raising" do
        File.write(File.join(tmpdir, "file.txt"), "content")
        sp = File.join(tmpdir, ".dave-props", "file.txt.json")
        FileUtils.mkdir_p(File.dirname(sp))
        File.write(sp, "not valid json{{{")
        expect(provider.get_properties("/file.txt")).to eq({})
      end
    end

    context "after properties have been set" do
      before do
        File.write(File.join(tmpdir, "file.txt"), "x")
        provider.set_properties("/file.txt", "{DAV:}displayname" => "My File")
      end

      it "returns the stored properties" do
        props = provider.get_properties("/file.txt")
        expect(props["{DAV:}displayname"]).to eq("My File")
      end
    end
  end

  # ──────────────────────────────────────────────
  # set_properties
  # ──────────────────────────────────────────────

  describe "#set_properties" do
    context "when the resource exists" do
      before { File.write(File.join(tmpdir, "file.txt"), "x") }

      it "stores properties retrievable via get_properties" do
        provider.set_properties("/file.txt", "{DAV:}displayname" => "Report")
        expect(provider.get_properties("/file.txt")["{DAV:}displayname"]).to eq("Report")
      end

      it "merges new properties with existing ones" do
        provider.set_properties("/file.txt", "{DAV:}displayname" => "Report")
        provider.set_properties("/file.txt", "{http://example.com/ns/}author" => "Alice")
        props = provider.get_properties("/file.txt")
        expect(props["{DAV:}displayname"]).to eq("Report")
        expect(props["{http://example.com/ns/}author"]).to eq("Alice")
      end

      it "overwrites an existing property value when the same key is set again" do
        provider.set_properties("/file.txt", "{DAV:}displayname" => "Old Name")
        provider.set_properties("/file.txt", "{DAV:}displayname" => "New Name")
        expect(provider.get_properties("/file.txt")["{DAV:}displayname"]).to eq("New Name")
      end

      it "supports custom namespace properties (round-trip)" do
        props_in = {
          "{http://example.com/ns/}author" => "<author>Alice</author>",
          "{http://ns.myapp.org/}priority" => "high"
        }
        provider.set_properties("/file.txt", props_in)
        props_out = provider.get_properties("/file.txt")
        expect(props_out["{http://example.com/ns/}author"]).to eq("<author>Alice</author>")
        expect(props_out["{http://ns.myapp.org/}priority"]).to eq("high")
      end
    end

    context "when the resource does not exist" do
      it "raises Dave::NotFoundError" do
        expect {
          provider.set_properties("/nonexistent.txt", "{DAV:}displayname" => "Report")
        }.to raise_error(Dave::NotFoundError)
      end
    end

    context "persistence across provider instances" do
      it "properties written by one instance are visible to a new instance pointing at the same root" do
        provider.write_content("/doc.txt", StringIO.new("content"))
        provider.set_properties("/doc.txt", "{DAV:}displayname" => "Persistent")

        new_provider = Dave::FileSystemProvider.new(root: tmpdir)
        expect(new_provider.get_properties("/doc.txt")["{DAV:}displayname"]).to eq("Persistent")
      end
    end

    context "for a collection resource" do
      before { Dir.mkdir(File.join(tmpdir, "mydir")) }

      it "stores and retrieves properties for a collection path" do
        provider.set_properties("/mydir/", "{DAV:}displayname" => "My Dir")
        expect(provider.get_properties("/mydir/")["{DAV:}displayname"]).to eq("My Dir")
      end
    end
  end

  # ──────────────────────────────────────────────
  # delete_properties
  # ──────────────────────────────────────────────

  describe "#delete_properties" do
    context "when the resource exists with properties set" do
      before do
        File.write(File.join(tmpdir, "file.txt"), "x")
        provider.set_properties("/file.txt", "{DAV:}displayname" => "Report", "{http://example.com/}foo" => "<foo/>")
      end

      it "removes named properties" do
        provider.delete_properties("/file.txt", ["{DAV:}displayname"])
        expect(provider.get_properties("/file.txt")).not_to have_key("{DAV:}displayname")
      end

      it "leaves other properties intact" do
        provider.delete_properties("/file.txt", ["{DAV:}displayname"])
        expect(provider.get_properties("/file.txt")["{http://example.com/}foo"]).to eq("<foo/>")
      end

      it "is silent (no error) when deleting a name that doesn't exist" do
        expect {
          provider.delete_properties("/file.txt", ["{DAV:}nonexistent"])
        }.not_to raise_error
      end
    end

    context "when the resource exists but has no sidecar" do
      before { File.write(File.join(tmpdir, "file.txt"), "x") }

      it "does nothing and does not raise" do
        expect {
          provider.delete_properties("/file.txt", ["{DAV:}displayname"])
        }.not_to raise_error
      end
    end

    context "when the resource does not exist" do
      it "raises Dave::NotFoundError" do
        expect {
          provider.delete_properties("/nonexistent.txt", ["{DAV:}displayname"])
        }.to raise_error(Dave::NotFoundError)
      end
    end
  end

  # ──────────────────────────────────────────────
  # sidecar_path mapping (private, tested indirectly via behaviour)
  # ──────────────────────────────────────────────

  describe "sidecar file path mapping" do
    it "stores properties for a nested file in the correct sidecar location" do
      Dir.mkdir(File.join(tmpdir, "documents"))
      File.write(File.join(tmpdir, "documents", "report.pdf"), "pdf")
      provider.set_properties("/documents/report.pdf", "{DAV:}displayname" => "Report PDF")

      sidecar = File.join(tmpdir, ".dave-props", "documents", "report.pdf.json")
      expect(File.exist?(sidecar)).to be true
    end

    it "stores properties for a collection in the correct sidecar location" do
      Dir.mkdir(File.join(tmpdir, "documents"))
      provider.set_properties("/documents/", "{DAV:}displayname" => "Documents")

      sidecar = File.join(tmpdir, ".dave-props", "documents", ".json")
      expect(File.exist?(sidecar)).to be true
    end

    it "stores properties for the root collection in the correct sidecar location" do
      provider.set_properties("/", "{DAV:}displayname" => "Root")

      sidecar = File.join(tmpdir, ".dave-props", ".json")
      expect(File.exist?(sidecar)).to be true
    end

    it "stores sidecar as valid JSON" do
      File.write(File.join(tmpdir, "file.txt"), "x")
      provider.set_properties("/file.txt", "{DAV:}displayname" => "Test")

      sidecar = File.join(tmpdir, ".dave-props", "file.txt.json")
      data = JSON.parse(File.read(sidecar))
      expect(data["{DAV:}displayname"]).to eq("Test")
    end
  end
end
