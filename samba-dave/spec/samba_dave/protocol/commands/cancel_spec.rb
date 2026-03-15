# frozen_string_literal: true

require "spec_helper"
require "samba_dave/protocol/commands/cancel"

RSpec.describe SambaDave::Protocol::Commands::Cancel do
  C = SambaDave::Protocol::Constants

  # Build CANCEL request body — StructureSize(2) + Reserved(2) = 4 bytes.
  def build_cancel_body
    [4, 0].pack("S<S<")
  end

  describe ".handle" do
    it "returns skip_response: true (no SMB2 response to CANCEL)" do
      result = described_class.handle(build_cancel_body)
      expect(result[:skip_response]).to be true
    end

    it "returns status nil (no response)" do
      result = described_class.handle(build_cancel_body)
      expect(result[:status]).to be_nil
    end

    it "returns body nil" do
      result = described_class.handle(build_cancel_body)
      expect(result[:body]).to be_nil
    end
  end
end
