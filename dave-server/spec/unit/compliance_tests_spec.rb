require "spec_helper"
require "dave/file_system_interface"

RSpec.describe Dave::FileSystemInterface::ComplianceTests do
  describe "self.included" do
    it "injects RSpec examples when included into a describe block" do
      # Verify the module responds to the expected interface
      expect(Dave::FileSystemInterface::ComplianceTests).to respond_to(:included)
    end

    it "ComplianceTests is a module" do
      expect(Dave::FileSystemInterface::ComplianceTests).to be_a(Module)
    end
  end
end
