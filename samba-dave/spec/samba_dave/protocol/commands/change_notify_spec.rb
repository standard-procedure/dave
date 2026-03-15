# frozen_string_literal: true

require "spec_helper"
require "samba_dave/protocol/commands/change_notify"

RSpec.describe SambaDave::Protocol::Commands::ChangeNotify do
  C = SambaDave::Protocol::Constants

  # Build a minimal CHANGE_NOTIFY request body.
  # MS-SMB2 section 2.2.35 — fixed 32-byte body:
  #   StructureSize (2) = 32
  #   Flags (2)
  #   OutputBufferLength (4)
  #   FileId.Persistent (8)
  #   FileId.Volatile (8)
  #   CompletionFilter (4)
  #   Reserved (4)
  def build_change_notify_body(file_id: "\x00" * 16)
    persistent = file_id[0, 8].unpack1("Q<")
    volatile   = file_id[8, 8].unpack1("Q<")
    [32, 0, 4096, persistent, volatile, 0x00000FFF, 0].pack("S<S<L<Q<Q<L<L<")
  end

  describe ".handle" do
    it "returns STATUS_NOT_SUPPORTED" do
      result = described_class.handle(build_change_notify_body)
      expect(result[:status]).to eq(C::Status::NOT_SUPPORTED)
    end

    it "returns an empty body" do
      result = described_class.handle(build_change_notify_body)
      expect(result[:body]).to eq("")
    end

    it "does not raise an exception" do
      expect { described_class.handle(build_change_notify_body) }.not_to raise_error
    end
  end
end
