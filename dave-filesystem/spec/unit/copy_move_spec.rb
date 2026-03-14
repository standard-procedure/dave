require "spec_helper"
require "tmpdir"
require "stringio"

RSpec.describe "Dave::FileSystemProvider copy/move with sidecar props" do
  let(:tmpdir) { Dir.mktmpdir }
  subject(:provider) { Dave::FileSystemProvider.new(root: tmpdir) }

  after { FileUtils.rm_rf(tmpdir) }

  # ──────────────────────────────────────────────
  # Helpers
  # ──────────────────────────────────────────────

  def write_file(rel_path, content = "data")
    abs = File.join(tmpdir, rel_path)
    FileUtils.mkdir_p(File.dirname(abs))
    File.write(abs, content)
  end

  def make_dir(rel_path)
    abs = File.join(tmpdir, rel_path)
    FileUtils.mkdir_p(abs)
  end

  def sidecar(rel_path)
    File.join(tmpdir, ".dave-props", rel_path)
  end

  def write_sidecar(rel_path, data)
    sp = sidecar(rel_path)
    FileUtils.mkdir_p(File.dirname(sp))
    File.write(sp, JSON.generate(data))
  end

  def read_sidecar(rel_path)
    sp = sidecar(rel_path)
    return nil unless File.exist?(sp)
    JSON.parse(File.read(sp))
  end

  # ══════════════════════════════════════════════
  # #copy — error conditions
  # ══════════════════════════════════════════════

  describe "#copy — error conditions" do
    it "raises Dave::NotFoundError when src does not exist" do
      expect {
        provider.copy("/nonexistent.txt", "/dst.txt")
      }.to raise_error(Dave::NotFoundError)
    end

    it "raises Dave::NotFoundError when parent of dst does not exist" do
      write_file("src.txt")
      expect {
        provider.copy("/src.txt", "/missing-parent/dst.txt")
      }.to raise_error(Dave::NotFoundError)
    end

    it "raises Dave::AlreadyExistsError when overwrite: false and dst exists" do
      write_file("src.txt")
      write_file("dst.txt")
      expect {
        provider.copy("/src.txt", "/dst.txt", overwrite: false)
      }.to raise_error(Dave::AlreadyExistsError)
    end
  end

  # ══════════════════════════════════════════════
  # #copy — return values
  # ══════════════════════════════════════════════

  describe "#copy — return values" do
    it "returns :created when destination did not previously exist" do
      write_file("src.txt")
      result = provider.copy("/src.txt", "/dst.txt")
      expect(result).to eq(:created)
    end

    it "returns :no_content when destination already existed" do
      write_file("src.txt")
      write_file("dst.txt")
      result = provider.copy("/src.txt", "/dst.txt")
      expect(result).to eq(:no_content)
    end
  end

  # ══════════════════════════════════════════════
  # #copy — file + sidecar
  # ══════════════════════════════════════════════

  describe "#copy — file with sidecar" do
    before do
      write_file("src.txt", "hello")
      write_sidecar("src.txt.json", "{DAV:}displayname" => "Source File")
    end

    it "copies the file content to the destination" do
      provider.copy("/src.txt", "/dst.txt")
      expect(File.read(File.join(tmpdir, "dst.txt"))).to eq("hello")
    end

    it "copies the sidecar props to the destination sidecar path" do
      provider.copy("/src.txt", "/dst.txt")
      expect(read_sidecar("dst.txt.json")).to eq("{DAV:}displayname" => "Source File")
    end

    it "leaves the source sidecar intact" do
      provider.copy("/src.txt", "/dst.txt")
      expect(read_sidecar("src.txt.json")).to eq("{DAV:}displayname" => "Source File")
    end

    it "does not create a sidecar at dst when src has no sidecar" do
      write_file("plain.txt", "no props")
      provider.copy("/plain.txt", "/plain-copy.txt")
      expect(File.exist?(sidecar("plain-copy.txt.json"))).to be false
    end
  end

  # ══════════════════════════════════════════════
  # #copy — file overwrite with sidecar cleanup
  # ══════════════════════════════════════════════

  describe "#copy — file overwrite" do
    it "overwrites destination file and replaces sidecar when overwrite: true" do
      write_file("src.txt", "new content")
      write_sidecar("src.txt.json", "{DAV:}displayname" => "New")
      write_file("dst.txt", "old content")
      write_sidecar("dst.txt.json", "{DAV:}displayname" => "Old")

      provider.copy("/src.txt", "/dst.txt", overwrite: true)

      expect(File.read(File.join(tmpdir, "dst.txt"))).to eq("new content")
      expect(read_sidecar("dst.txt.json")).to eq("{DAV:}displayname" => "New")
    end
  end

  # ══════════════════════════════════════════════
  # #copy — collection depth: :infinity
  # ══════════════════════════════════════════════

  describe "#copy — collection with depth: :infinity" do
    before do
      make_dir("src")
      write_file("src/a.txt", "aaa")
      write_file("src/sub/b.txt", "bbb")
      write_sidecar("src/.json", "{DAV:}displayname" => "Src Dir")
      write_sidecar("src/a.txt.json", "{DAV:}displayname" => "File A")
      write_sidecar("src/sub/.json", "{DAV:}displayname" => "Sub Dir")
      write_sidecar("src/sub/b.txt.json", "{DAV:}displayname" => "File B")
    end

    it "copies all files recursively" do
      provider.copy("/src/", "/dst/")
      expect(File.read(File.join(tmpdir, "dst", "a.txt"))).to eq("aaa")
      expect(File.read(File.join(tmpdir, "dst", "sub", "b.txt"))).to eq("bbb")
    end

    it "copies the collection's own sidecar props" do
      provider.copy("/src/", "/dst/")
      expect(read_sidecar("dst/.json")).to eq("{DAV:}displayname" => "Src Dir")
    end

    it "copies member file sidecars" do
      provider.copy("/src/", "/dst/")
      expect(read_sidecar("dst/a.txt.json")).to eq("{DAV:}displayname" => "File A")
    end

    it "copies nested subcollection sidecars" do
      provider.copy("/src/", "/dst/")
      expect(read_sidecar("dst/sub/.json")).to eq("{DAV:}displayname" => "Sub Dir")
    end

    it "copies nested member file sidecars" do
      provider.copy("/src/", "/dst/")
      expect(read_sidecar("dst/sub/b.txt.json")).to eq("{DAV:}displayname" => "File B")
    end

    it "leaves the source directory and its sidecars intact" do
      provider.copy("/src/", "/dst/")
      expect(File.exist?(File.join(tmpdir, "src", "a.txt"))).to be true
      expect(read_sidecar("src/a.txt.json")).to eq("{DAV:}displayname" => "File A")
    end

    it "returns :created when dst did not exist" do
      expect(provider.copy("/src/", "/dst/")).to eq(:created)
    end
  end

  # ══════════════════════════════════════════════
  # #copy — collection depth: :zero
  # ══════════════════════════════════════════════

  describe "#copy — collection with depth: :zero" do
    before do
      make_dir("src")
      write_file("src/a.txt", "aaa")
      write_sidecar("src/.json", "{DAV:}displayname" => "Src Dir")
      write_sidecar("src/a.txt.json", "{DAV:}displayname" => "File A")
    end

    it "creates an empty directory at dst" do
      provider.copy("/src/", "/dst/", depth: :zero)
      expect(File.directory?(File.join(tmpdir, "dst"))).to be true
    end

    it "does NOT copy members into dst" do
      provider.copy("/src/", "/dst/", depth: :zero)
      expect(File.exist?(File.join(tmpdir, "dst", "a.txt"))).to be false
    end

    it "copies the collection's own sidecar props" do
      provider.copy("/src/", "/dst/", depth: :zero)
      expect(read_sidecar("dst/.json")).to eq("{DAV:}displayname" => "Src Dir")
    end

    it "does NOT copy member sidecars" do
      provider.copy("/src/", "/dst/", depth: :zero)
      expect(File.exist?(sidecar("dst/a.txt.json"))).to be false
    end
  end

  # ══════════════════════════════════════════════
  # #move — error conditions
  # ══════════════════════════════════════════════

  describe "#move — error conditions" do
    it "raises Dave::NotFoundError when src does not exist" do
      expect {
        provider.move("/nonexistent.txt", "/dst.txt")
      }.to raise_error(Dave::NotFoundError)
    end

    it "raises Dave::NotFoundError when parent of dst does not exist" do
      write_file("src.txt")
      expect {
        provider.move("/src.txt", "/missing-parent/dst.txt")
      }.to raise_error(Dave::NotFoundError)
    end

    it "raises Dave::AlreadyExistsError when overwrite: false and dst exists" do
      write_file("src.txt")
      write_file("dst.txt")
      expect {
        provider.move("/src.txt", "/dst.txt", overwrite: false)
      }.to raise_error(Dave::AlreadyExistsError)
    end
  end

  # ══════════════════════════════════════════════
  # #move — return values
  # ══════════════════════════════════════════════

  describe "#move — return values" do
    it "returns :created when destination did not previously exist" do
      write_file("src.txt")
      expect(provider.move("/src.txt", "/dst.txt")).to eq(:created)
    end

    it "returns :no_content when destination already existed" do
      write_file("src.txt")
      write_file("dst.txt")
      expect(provider.move("/src.txt", "/dst.txt")).to eq(:no_content)
    end
  end

  # ══════════════════════════════════════════════
  # #move — file + sidecar
  # ══════════════════════════════════════════════

  describe "#move — file with sidecar" do
    before do
      write_file("src.txt", "hello")
      write_sidecar("src.txt.json", "{DAV:}displayname" => "Source File")
    end

    it "moves the file content to the destination" do
      provider.move("/src.txt", "/dst.txt")
      expect(File.read(File.join(tmpdir, "dst.txt"))).to eq("hello")
    end

    it "removes the source file" do
      provider.move("/src.txt", "/dst.txt")
      expect(File.exist?(File.join(tmpdir, "src.txt"))).to be false
    end

    it "moves the sidecar props to the destination sidecar path" do
      provider.move("/src.txt", "/dst.txt")
      expect(read_sidecar("dst.txt.json")).to eq("{DAV:}displayname" => "Source File")
    end

    it "removes the source sidecar" do
      provider.move("/src.txt", "/dst.txt")
      expect(File.exist?(sidecar("src.txt.json"))).to be false
    end

    it "does not create a sidecar at dst when src had no sidecar" do
      write_file("plain.txt", "no props")
      provider.move("/plain.txt", "/plain-moved.txt")
      expect(File.exist?(sidecar("plain-moved.txt.json"))).to be false
    end
  end

  # ══════════════════════════════════════════════
  # #move — file overwrite
  # ══════════════════════════════════════════════

  describe "#move — file overwrite" do
    it "overwrites destination and replaces its sidecar when overwrite: true" do
      write_file("src.txt", "new content")
      write_sidecar("src.txt.json", "{DAV:}displayname" => "New")
      write_file("dst.txt", "old content")
      write_sidecar("dst.txt.json", "{DAV:}displayname" => "Old")

      provider.move("/src.txt", "/dst.txt", overwrite: true)

      expect(File.read(File.join(tmpdir, "dst.txt"))).to eq("new content")
      expect(read_sidecar("dst.txt.json")).to eq("{DAV:}displayname" => "New")
      expect(File.exist?(File.join(tmpdir, "src.txt"))).to be false
    end
  end

  # ══════════════════════════════════════════════
  # #move — collection
  # ══════════════════════════════════════════════

  describe "#move — collection with sidecar subtree" do
    before do
      make_dir("src")
      write_file("src/a.txt", "aaa")
      write_file("src/sub/b.txt", "bbb")
      write_sidecar("src/.json", "{DAV:}displayname" => "Src Dir")
      write_sidecar("src/a.txt.json", "{DAV:}displayname" => "File A")
      write_sidecar("src/sub/.json", "{DAV:}displayname" => "Sub Dir")
      write_sidecar("src/sub/b.txt.json", "{DAV:}displayname" => "File B")
    end

    it "moves all files to the destination" do
      provider.move("/src/", "/dst/")
      expect(File.read(File.join(tmpdir, "dst", "a.txt"))).to eq("aaa")
      expect(File.read(File.join(tmpdir, "dst", "sub", "b.txt"))).to eq("bbb")
    end

    it "removes the source directory" do
      provider.move("/src/", "/dst/")
      expect(File.exist?(File.join(tmpdir, "src"))).to be false
    end

    it "moves the collection's own sidecar props" do
      provider.move("/src/", "/dst/")
      expect(read_sidecar("dst/.json")).to eq("{DAV:}displayname" => "Src Dir")
    end

    it "moves member file sidecars" do
      provider.move("/src/", "/dst/")
      expect(read_sidecar("dst/a.txt.json")).to eq("{DAV:}displayname" => "File A")
    end

    it "moves nested subcollection sidecars" do
      provider.move("/src/", "/dst/")
      expect(read_sidecar("dst/sub/.json")).to eq("{DAV:}displayname" => "Sub Dir")
    end

    it "moves nested member file sidecars" do
      provider.move("/src/", "/dst/")
      expect(read_sidecar("dst/sub/b.txt.json")).to eq("{DAV:}displayname" => "File B")
    end

    it "removes the source sidecar subtree" do
      provider.move("/src/", "/dst/")
      expect(File.exist?(sidecar("src"))).to be false
    end
  end
end
