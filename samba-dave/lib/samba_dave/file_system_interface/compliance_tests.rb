# frozen_string_literal: true

require "dave/file_system_interface"

module SambaDave
  module FileSystemInterface
    # SMB2-facing compliance for a Dave::FileSystemInterface provider.
    #
    # The bulk of the FileSystemInterface contract is identical whether it is
    # driven by WebDAV or SMB, so rather than maintain a second divergent copy
    # of those examples this suite reuses the canonical shared examples
    # (Dave::FileSystemInterface::ComplianceTests) as the single source of
    # truth, and adds only the QUERY_INFO metadata guarantees that SMB needs
    # over and above WebDAV (FileBasic/Standard/InternalInformation fields).
    #
    # Usage in a spec file:
    #
    #   RSpec.describe MyProvider do
    #     subject { MyProvider.new(...) }
    #     include SambaDave::FileSystemInterface::ComplianceTests
    #   end
    #
    # The subject must be a configured provider instance that starts with an
    # empty, writable root collection ("/").
    module ComplianceTests
      def self.included(base)
        # Pull in the full shared interface contract.
        base.include Dave::FileSystemInterface::ComplianceTests

        # SMB-only additions: fields SMB's QUERY_INFO responses require that
        # the WebDAV-oriented shared suite does not assert.
        base.describe "SMB QUERY_INFO metadata requirements" do
          it "resource exposes a last_modified Time (FileBasicInformation)" do
            subject.write_content("/smb-meta.txt", StringIO.new("x"))
            expect(subject.get_resource("/smb-meta.txt").last_modified).to be_a(Time)
          end

          it "resource exposes a created_at Time (FileBasicInformation)" do
            subject.write_content("/smb-ctime.txt", StringIO.new("x"))
            expect(subject.get_resource("/smb-ctime.txt").created_at).to be_a(Time)
          end

          it "resource exposes an Integer content_length (FileStandardInformation)" do
            subject.write_content("/smb-size.txt", StringIO.new("12345"))
            resource = subject.get_resource("/smb-size.txt")
            expect(resource.content_length).to be_a(Integer)
            expect(resource.content_length).to eq(5)
          end

          it "resource exposes a non-empty etag String (FileInternalInformation)" do
            subject.write_content("/smb-etag.txt", StringIO.new("x"))
            etag = subject.get_resource("/smb-etag.txt").etag
            expect(etag).to be_a(String)
            expect(etag).not_to be_empty
          end
        end
      end
    end
  end
end
