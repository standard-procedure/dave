# frozen_string_literal: true

require "spec_helper"
require "samba_dave/protocol/commands/echo"

RSpec.describe SambaDave::Protocol::Commands::Echo do
  C = SambaDave::Protocol::Constants

  describe ".handle" do
    it "returns STATUS_SUCCESS" do
      result = described_class.handle("")
      expect(result[:status]).to eq(C::Status::SUCCESS)
    end

    it "returns a 4-byte response body" do
      result = described_class.handle("")
      expect(result[:body].bytesize).to eq(4)
    end

    it "returns StructureSize=4 in the response" do
      result = described_class.handle("")
      response = SambaDave::Protocol::Commands::EchoResponse.read(result[:body])
      expect(response.structure_size).to eq(4)
    end
  end
end
