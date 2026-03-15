# frozen_string_literal: true

require "spec_helper"
require "samba_dave/protocol/commands/lock"

RSpec.describe SambaDave::Protocol::Commands::Lock do
  C = SambaDave::Protocol::Constants

  # Build a minimal LOCK request body.
  # MS-SMB2 section 2.2.26 — fixed 48-byte body:
  #   StructureSize (2) = 48
  #   LockCount (2)
  #   LockSequenceNumber (4)
  #   FileId.Persistent (8)
  #   FileId.Volatile (8)
  #   Locks[] (24 bytes each)
  def build_lock_body(file_id: "\x00" * 16)
    persistent = file_id[0, 8].unpack1("Q<")
    volatile   = file_id[8, 8].unpack1("Q<")
    # One lock entry: Offset(8) Length(8) Flags(4) Reserved(4) = 24 bytes
    lock_entry = [0, 0, 1, 0].pack("Q<Q<L<L<")
    [48, 1, 0, persistent, volatile].pack("S<S<L<Q<Q<") + lock_entry
  end

  describe ".handle" do
    it "returns STATUS_NOT_SUPPORTED" do
      result = described_class.handle(build_lock_body)
      expect(result[:status]).to eq(C::Status::NOT_SUPPORTED)
    end

    it "returns an empty body" do
      result = described_class.handle(build_lock_body)
      expect(result[:body]).to eq("")
    end

    it "does not raise an exception" do
      expect { described_class.handle(build_lock_body) }.not_to raise_error
    end
  end
end
