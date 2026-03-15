# frozen_string_literal: true

require "spec_helper"
require "samba_dave/tree_connect"

RSpec.describe SambaDave::TreeConnect do
  let(:filesystem) { double("FileSystemProvider") }

  describe "#initialize" do
    it "stores tree_id" do
      tc = described_class.new(tree_id: 7, share_name: "files", filesystem: filesystem)
      expect(tc.tree_id).to eq(7)
    end

    it "stores share_name" do
      tc = described_class.new(tree_id: 1, share_name: "myshare", filesystem: filesystem)
      expect(tc.share_name).to eq("myshare")
    end

    it "stores filesystem reference" do
      tc = described_class.new(tree_id: 1, share_name: "files", filesystem: filesystem)
      expect(tc.filesystem).to eq(filesystem)
    end
  end

  describe "multiple tree connects" do
    it "each has its own tree_id and share" do
      fs1 = double("fs1")
      fs2 = double("fs2")
      tc1 = described_class.new(tree_id: 1, share_name: "alpha", filesystem: fs1)
      tc2 = described_class.new(tree_id: 2, share_name: "beta",  filesystem: fs2)

      expect(tc1.tree_id).to eq(1)
      expect(tc2.tree_id).to eq(2)
      expect(tc1.share_name).not_to eq(tc2.share_name)
      expect(tc1.filesystem).not_to eq(tc2.filesystem)
    end
  end
end
