require "spec_helper"
require "tmpdir"

RSpec.describe Dave::FileSystemProvider do
  let(:tmpdir) { Dir.mktmpdir }
  subject { Dave::FileSystemProvider.new(root: tmpdir) }

  include Dave::FileSystemInterface::ComplianceTests

  after { FileUtils.rm_rf(tmpdir) }
end
