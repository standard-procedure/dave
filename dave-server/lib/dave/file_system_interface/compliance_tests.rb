# Defined in dave-server/lib/dave/file_system_interface/compliance_tests.rb
module Dave
  module FileSystemInterface
    module ComplianceTests
      def self.included(base)
        base.describe "FileSystem Provider compliance" do
          # subject must be set to a configured provider instance in the including spec

          it "returns nil for non-existent paths" do
            expect(subject.get_resource("/nonexistent")).to be_nil
          end

          it "returns a Resource with collection: false for an existing file" do
            subject.write_content("/file.txt", StringIO.new("data"))
            resource = subject.get_resource("/file.txt")
            expect(resource).not_to be_nil
            expect(resource.collection?).to be false
          end

          it "returns a Resource with collection: true for an existing directory" do
            subject.create_collection("/somedir/")
            resource = subject.get_resource("/somedir/")
            expect(resource).not_to be_nil
            expect(resource.collection?).to be true
          end

          it "lists children of the root collection" do
            expect(subject.list_children("/")).to be_an(Array)
          end

          it "returns nil from list_children for a non-collection path" do
            subject.write_content("/notadir.txt", StringIO.new("x"))
            expect(subject.list_children("/notadir.txt")).to be_nil
          end

          it "creates a resource and reads it back" do
            subject.write_content("/test.txt", StringIO.new("hello"), content_type: "text/plain")
            resource = subject.get_resource("/test.txt")
            expect(resource).not_to be_nil
            expect(resource.collection?).to be false
            expect(resource.content_length).to eq(5)
            expect(subject.read_content("/test.txt").read).to eq("hello")
          end

          it "read_content returns an IO-like object" do
            subject.write_content("/io.txt", StringIO.new("io test"))
            io = subject.read_content("/io.txt")
            expect(io).to respond_to(:read)
            expect(io).to respond_to(:each)
          end

          it "write_content returns a quoted ETag string" do
            etag = subject.write_content("/etag-return.txt", StringIO.new("content"))
            expect(etag).to match(/\A"[^"]+"\z/)
          end

          it "write_content overwrites an existing file" do
            subject.write_content("/overwrite.txt", StringIO.new("first"))
            subject.write_content("/overwrite.txt", StringIO.new("second"))
            expect(subject.read_content("/overwrite.txt").read).to eq("second")
          end

          it "creates a collection" do
            subject.create_collection("/mydir/")
            resource = subject.get_resource("/mydir/")
            expect(resource).not_to be_nil
            expect(resource.collection?).to be true
          end

          it "raises NotFoundError when creating collection with missing parent" do
            expect { subject.create_collection("/missing-parent/subdir/") }
              .to raise_error(Dave::NotFoundError)
          end

          it "lists collection children after writes" do
            subject.write_content("/a.txt", StringIO.new("a"))
            subject.write_content("/b.txt", StringIO.new("b"))
            paths = subject.list_children("/").map(&:path)
            expect(paths).to include("/a.txt", "/b.txt")
          end

          it "deletes a resource" do
            subject.write_content("/deleteme.txt", StringIO.new("bye"))
            subject.delete("/deleteme.txt")
            expect(subject.get_resource("/deleteme.txt")).to be_nil
          end

          it "raises NotFoundError when deleting non-existent resource" do
            expect { subject.delete("/nonexistent.txt") }.to raise_error(Dave::NotFoundError)
          end

          it "delete returns an empty array on success (file)" do
            subject.write_content("/deleteme2.txt", StringIO.new("bye"))
            result = subject.delete("/deleteme2.txt")
            expect(result).to eq([])
          end

          it "deletes a collection recursively" do
            subject.create_collection("/dir/")
            subject.write_content("/dir/file.txt", StringIO.new("x"))
            subject.delete("/dir/")
            expect(subject.get_resource("/dir/")).to be_nil
            expect(subject.get_resource("/dir/file.txt")).to be_nil
          end

          it "delete returns an empty array on success (collection)" do
            subject.create_collection("/dircol/")
            result = subject.delete("/dircol/")
            expect(result).to eq([])
          end

          it "copies a resource" do
            subject.write_content("/src.txt", StringIO.new("copy me"))
            subject.copy("/src.txt", "/dst.txt")
            expect(subject.read_content("/dst.txt").read).to eq("copy me")
            expect(subject.get_resource("/src.txt")).not_to be_nil
          end

          it "copy returns :created when destination is new" do
            subject.write_content("/copy-new-src.txt", StringIO.new("x"))
            result = subject.copy("/copy-new-src.txt", "/copy-new-dst.txt")
            expect(result).to eq(:created)
          end

          it "copy returns :no_content when destination is overwritten" do
            subject.write_content("/copy-ow-src.txt", StringIO.new("x"))
            subject.write_content("/copy-ow-dst.txt", StringIO.new("y"))
            result = subject.copy("/copy-ow-src.txt", "/copy-ow-dst.txt", overwrite: true)
            expect(result).to eq(:no_content)
          end

          it "raises AlreadyExistsError on copy with overwrite: false when destination exists" do
            subject.write_content("/copy-src.txt", StringIO.new("x"))
            subject.write_content("/copy-dst.txt", StringIO.new("y"))
            expect { subject.copy("/copy-src.txt", "/copy-dst.txt", overwrite: false) }
              .to raise_error(Dave::AlreadyExistsError)
          end

          it "moves a resource" do
            subject.write_content("/old.txt", StringIO.new("move me"))
            subject.move("/old.txt", "/new.txt")
            expect(subject.get_resource("/old.txt")).to be_nil
            expect(subject.read_content("/new.txt").read).to eq("move me")
          end

          it "move returns :created when destination is new" do
            subject.write_content("/move-new-src.txt", StringIO.new("x"))
            result = subject.move("/move-new-src.txt", "/move-new-dst.txt")
            expect(result).to eq(:created)
          end

          it "move returns :no_content when destination is overwritten" do
            subject.write_content("/move-ow-src.txt", StringIO.new("x"))
            subject.write_content("/move-ow-dst.txt", StringIO.new("y"))
            result = subject.move("/move-ow-src.txt", "/move-ow-dst.txt", overwrite: true)
            expect(result).to eq(:no_content)
          end

          it "source is gone after move" do
            subject.write_content("/move-src.txt", StringIO.new("gone"))
            subject.move("/move-src.txt", "/move-dst.txt")
            expect(subject.get_resource("/move-src.txt")).to be_nil
          end

          it "stores and retrieves dead properties" do
            subject.write_content("/props.txt", StringIO.new("x"))
            subject.set_properties("/props.txt", "{http://example.com/}author" => "<author>Alice</author>")
            props = subject.get_properties("/props.txt")
            expect(props["{http://example.com/}author"]).to eq("<author>Alice</author>")
          end

          it "removes dead properties" do
            subject.write_content("/props.txt", StringIO.new("x"))
            subject.set_properties("/props.txt", "{http://example.com/}foo" => "<foo/>")
            subject.delete_properties("/props.txt", ["{http://example.com/}foo"])
            expect(subject.get_properties("/props.txt")).not_to have_key("{http://example.com/}foo")
          end

          it "changes ETag on write" do
            subject.write_content("/etag.txt", StringIO.new("v1"))
            etag1 = subject.get_resource("/etag.txt").etag
            subject.write_content("/etag.txt", StringIO.new("v2"))
            etag2 = subject.get_resource("/etag.txt").etag
            expect(etag1).not_to eq(etag2)
          end

          it "supports_locking? returns a Boolean" do
            result = subject.supports_locking?
            expect(result).to satisfy { |v| v == true || v == false }
          end

          it "quota_available_bytes returns Integer or nil" do
            result = subject.quota_available_bytes("/")
            expect(result).to satisfy { |v| v.nil? || v.is_a?(Integer) }
          end

          it "quota_used_bytes returns Integer or nil" do
            result = subject.quota_used_bytes("/")
            expect(result).to satisfy { |v| v.nil? || v.is_a?(Integer) }
          end

          it "raises NotFoundError when reading missing resource" do
            expect { subject.read_content("/missing") }.to raise_error(Dave::NotFoundError)
          end

          it "raises NotFoundError when writing to missing parent" do
            expect { subject.write_content("/missing-parent/file.txt", StringIO.new("x")) }
              .to raise_error(Dave::NotFoundError)
          end

          it "raises AlreadyExistsError when creating existing collection" do
            subject.create_collection("/existing/")
            expect { subject.create_collection("/existing/") }
              .to raise_error(Dave::AlreadyExistsError)
          end
        end
      end
    end
  end
end
