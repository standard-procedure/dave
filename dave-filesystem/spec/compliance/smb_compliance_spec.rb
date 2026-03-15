# frozen_string_literal: true

require "spec_helper"
require "tmpdir"
require "samba_dave/file_system_interface/compliance_tests"

# Proves that Dave::FileSystemProvider correctly implements the
# FileSystemInterface required by samba-dave (SMB2 server), not just WebDAV.
#
# This spec is the SMB counterpart to provider_compliance_spec.rb (WebDAV).

RSpec.describe Dave::FileSystemProvider do
  let(:tmpdir) { Dir.mktmpdir }
  subject      { Dave::FileSystemProvider.new(root: tmpdir) }

  include SambaDave::FileSystemInterface::ComplianceTests

  after { FileUtils.rm_rf(tmpdir) }
end
