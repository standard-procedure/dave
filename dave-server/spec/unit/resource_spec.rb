require "spec_helper"
require "dave/resource"

RSpec.describe Dave::Resource do
  let(:now) { Time.now }
  let(:created) { now - 3600 }

  let(:attributes) do
    {
      path: "/files/document.txt",
      collection: false,
      content_type: "text/plain",
      content_length: 1024,
      etag: '"abc123"',
      last_modified: now,
      created_at: created
    }
  end

  subject(:resource) { described_class.new(**attributes) }

  describe "construction" do
    it "can be created with all fields" do
      expect { described_class.new(**attributes) }.not_to raise_error
    end

    it "exposes path" do
      expect(resource.path).to eq("/files/document.txt")
    end

    it "exposes collection" do
      expect(resource.collection).to be(false)
    end

    it "exposes content_type" do
      expect(resource.content_type).to eq("text/plain")
    end

    it "exposes content_length" do
      expect(resource.content_length).to eq(1024)
    end

    it "exposes etag" do
      expect(resource.etag).to eq('"abc123"')
    end

    it "exposes last_modified" do
      expect(resource.last_modified).to eq(now)
    end

    it "exposes created_at" do
      expect(resource.created_at).to eq(created)
    end
  end

  describe "#collection?" do
    context "when collection is false" do
      it "returns false" do
        expect(resource.collection?).to be(false)
      end
    end

    context "when collection is true" do
      subject(:collection_resource) do
        described_class.new(**attributes.merge(collection: true, content_type: nil, content_length: nil))
      end

      it "returns true" do
        expect(collection_resource.collection?).to be(true)
      end
    end
  end

  describe "immutability" do
    it "is frozen" do
      expect(resource).to be_frozen
    end

    it "with() returns a new object with the updated field, leaving the original unchanged" do
      new_resource = resource.with(path: "/other/path.txt")
      expect(new_resource.path).to eq("/other/path.txt")
      expect(resource.path).to eq("/files/document.txt")
    end
  end

  describe "equality" do
    it "is equal to another Resource with the same fields" do
      other = described_class.new(**attributes)
      expect(resource).to eq(other)
    end

    it "is not equal to a Resource with different fields" do
      other = described_class.new(**attributes.merge(path: "/other/file.txt"))
      expect(resource).not_to eq(other)
    end
  end

  describe "nil fields for collections" do
    subject(:collection_resource) do
      described_class.new(
        path: "/collections/",
        collection: true,
        content_type: nil,
        content_length: nil,
        etag: '"col456"',
        last_modified: now,
        created_at: created
      )
    end

    it "allows nil content_type for collections" do
      expect(collection_resource.content_type).to be_nil
    end

    it "allows nil content_length for collections" do
      expect(collection_resource.content_length).to be_nil
    end

    it "collection? returns true" do
      expect(collection_resource.collection?).to be(true)
    end
  end
end
