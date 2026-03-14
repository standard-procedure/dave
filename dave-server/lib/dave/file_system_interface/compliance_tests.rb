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

          it "lists children of the root collection" do
            expect(subject.list_children("/")).to be_an(Array)
          end

          it "creates a resource and reads it back" do
            subject.write_content("/test.txt", StringIO.new("hello"), content_type: "text/plain")
            resource = subject.get_resource("/test.txt")
            expect(resource).not_to be_nil
            expect(resource.collection?).to be false
            expect(resource.content_length).to eq(5)
            expect(subject.read_content("/test.txt").read).to eq("hello")
          end

          it "creates a collection" do
            subject.create_collection("/mydir/")
            resource = subject.get_resource("/mydir/")
            expect(resource).not_to be_nil
            expect(resource.collection?).to be true
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

          it "deletes a collection recursively" do
            subject.create_collection("/dir/")
            subject.write_content("/dir/file.txt", StringIO.new("x"))
            subject.delete("/dir/")
            expect(subject.get_resource("/dir/")).to be_nil
            expect(subject.get_resource("/dir/file.txt")).to be_nil
          end

          it "copies a resource" do
            subject.write_content("/src.txt", StringIO.new("copy me"))
            subject.copy("/src.txt", "/dst.txt")
            expect(subject.read_content("/dst.txt").read).to eq("copy me")
            expect(subject.get_resource("/src.txt")).not_to be_nil
          end

          it "moves a resource" do
            subject.write_content("/old.txt", StringIO.new("move me"))
            subject.move("/old.txt", "/new.txt")
            expect(subject.get_resource("/old.txt")).to be_nil
            expect(subject.read_content("/new.txt").read).to eq("move me")
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
