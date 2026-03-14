require "spec_helper"
require "dave/lock_manager"

RSpec.describe Dave::LockManager do
  subject(:manager) { described_class.new }

  let(:path) { "/files/document.txt" }
  let(:collection_path) { "/files/" }

  # ─── acquire ────────────────────────────────────────────────────────────────

  describe "#acquire" do
    context "new exclusive lock" do
      it "returns a LockInfo" do
        result = manager.acquire(path, scope: :exclusive, depth: :zero)
        expect(result).to be_a(Dave::LockInfo)
      end

      it "sets the token as a urn:uuid: string" do
        result = manager.acquire(path, scope: :exclusive, depth: :zero)
        expect(result.token).to match(/\Aurn:uuid:[0-9a-f\-]{36}\z/)
      end

      it "sets path, scope, depth" do
        result = manager.acquire(path, scope: :exclusive, depth: :zero)
        expect(result.path).to eq(path)
        expect(result.scope).to eq(:exclusive)
        expect(result.depth).to eq(:zero)
      end

      it "sets type to :write" do
        result = manager.acquire(path, scope: :exclusive, depth: :zero)
        expect(result.type).to eq(:write)
      end

      it "sets created_at to approximately now" do
        before = Time.now
        result = manager.acquire(path, scope: :exclusive, depth: :zero)
        after  = Time.now
        expect(result.created_at).to be_between(before, after)
      end

      it "stores the owner when provided" do
        result = manager.acquire(path, scope: :exclusive, depth: :zero, owner: "<D:href>user</D:href>")
        expect(result.owner).to eq("<D:href>user</D:href>")
      end

      it "stores the principal when provided" do
        result = manager.acquire(path, scope: :exclusive, depth: :zero, principal: "alice")
        expect(result.principal).to eq("alice")
      end

      it "defaults timeout to 3600" do
        result = manager.acquire(path, scope: :exclusive, depth: :zero)
        expect(result.timeout).to eq(3600)
      end

      it "accepts a custom timeout" do
        result = manager.acquire(path, scope: :exclusive, depth: :zero, timeout: 7200)
        expect(result.timeout).to eq(7200)
      end

      it "accepts :infinite timeout" do
        result = manager.acquire(path, scope: :exclusive, depth: :zero, timeout: :infinite)
        expect(result.timeout).to eq(:infinite)
      end
    end

    context "new shared lock" do
      it "returns a LockInfo with scope :shared" do
        result = manager.acquire(path, scope: :shared, depth: :zero)
        expect(result.scope).to eq(:shared)
      end
    end

    context "lock conflicts" do
      it "raises LockConflictError when acquiring exclusive lock on an already-exclusively-locked path" do
        manager.acquire(path, scope: :exclusive, depth: :zero)
        expect {
          manager.acquire(path, scope: :exclusive, depth: :zero)
        }.to raise_error(Dave::LockConflictError)
      end

      it "raises LockConflictError when acquiring exclusive lock on a shared-locked path" do
        manager.acquire(path, scope: :shared, depth: :zero)
        expect {
          manager.acquire(path, scope: :exclusive, depth: :zero)
        }.to raise_error(Dave::LockConflictError)
      end

      it "raises LockConflictError when acquiring shared lock on an exclusively-locked path" do
        manager.acquire(path, scope: :exclusive, depth: :zero)
        expect {
          manager.acquire(path, scope: :shared, depth: :zero)
        }.to raise_error(Dave::LockConflictError)
      end

      it "does NOT raise when acquiring a second shared lock on a shared-locked path" do
        manager.acquire(path, scope: :shared, depth: :zero)
        expect {
          manager.acquire(path, scope: :shared, depth: :zero)
        }.not_to raise_error
      end

      it "raises LockConflictError when ancestor has a depth:infinity lock" do
        manager.acquire(collection_path, scope: :exclusive, depth: :infinity)
        expect {
          manager.acquire(path, scope: :exclusive, depth: :zero)
        }.to raise_error(Dave::LockConflictError)
      end

      it "does NOT raise when ancestor has a depth:zero lock" do
        manager.acquire(collection_path, scope: :exclusive, depth: :zero)
        expect {
          manager.acquire(path, scope: :exclusive, depth: :zero)
        }.not_to raise_error
      end

      it "does NOT conflict when the existing lock is expired" do
        manager.acquire(path, scope: :exclusive, depth: :zero, timeout: 1)
        # Fake expiry by travelling in time
        allow(Time).to receive(:now).and_return(Time.now + 3600)
        expect {
          manager.acquire(path, scope: :exclusive, depth: :zero)
        }.not_to raise_error
      end
    end
  end

  # ─── refresh ────────────────────────────────────────────────────────────────

  describe "#refresh" do
    let!(:lock) { manager.acquire(path, scope: :exclusive, depth: :zero, timeout: 3600) }

    it "returns an updated LockInfo with the new timeout" do
      result = manager.refresh(lock.token, timeout: 7200)
      expect(result.timeout).to eq(7200)
    end

    it "preserves other fields" do
      result = manager.refresh(lock.token, timeout: 7200)
      expect(result.path).to eq(lock.path)
      expect(result.scope).to eq(lock.scope)
      expect(result.token).to eq(lock.token)
    end

    it "raises LockNotFoundError for an unknown token" do
      expect {
        manager.refresh("urn:uuid:unknown-token", timeout: 3600)
      }.to raise_error(Dave::LockNotFoundError)
    end

    it "raises LockNotFoundError when the lock has expired" do
      allow(Time).to receive(:now).and_return(Time.now + 3600)
      expect {
        manager.refresh(lock.token, timeout: 7200)
      }.to raise_error(Dave::LockNotFoundError)
    end
  end

  # ─── release ────────────────────────────────────────────────────────────────

  describe "#release" do
    let!(:lock) { manager.acquire(path, scope: :exclusive, depth: :zero) }

    it "returns true and removes the lock for a known token" do
      expect(manager.release(lock.token)).to be(true)
      expect(manager.locks_for(path)).to be_empty
    end

    it "returns false for an unknown token" do
      expect(manager.release("urn:uuid:nonexistent")).to be(false)
    end
  end

  # ─── locks_for ──────────────────────────────────────────────────────────────

  describe "#locks_for" do
    it "returns the direct lock on the path" do
      lock = manager.acquire(path, scope: :exclusive, depth: :zero)
      expect(manager.locks_for(path)).to include(lock)
    end

    it "returns an inherited lock from an ancestor with depth:infinity" do
      parent_lock = manager.acquire(collection_path, scope: :exclusive, depth: :infinity)
      expect(manager.locks_for(path)).to include(parent_lock)
    end

    it "does NOT return an ancestor lock with depth:zero" do
      manager.acquire(collection_path, scope: :exclusive, depth: :zero)
      expect(manager.locks_for(path)).to be_empty
    end

    it "returns an empty array when no locks exist" do
      expect(manager.locks_for(path)).to eq([])
    end

    it "does NOT return expired locks" do
      manager.acquire(path, scope: :exclusive, depth: :zero, timeout: 1)
      allow(Time).to receive(:now).and_return(Time.now + 3600)
      expect(manager.locks_for(path)).to be_empty
    end
  end

  # ─── locked? ────────────────────────────────────────────────────────────────

  describe "#locked?" do
    it "returns true when path has a direct lock" do
      manager.acquire(path, scope: :exclusive, depth: :zero)
      expect(manager.locked?(path)).to be(true)
    end

    it "returns true when an ancestor has a depth:infinity lock" do
      manager.acquire(collection_path, scope: :exclusive, depth: :infinity)
      expect(manager.locked?(path)).to be(true)
    end

    it "returns false when no lock exists" do
      expect(manager.locked?(path)).to be(false)
    end

    it "returns false when the only lock is expired" do
      manager.acquire(path, scope: :exclusive, depth: :zero, timeout: 1)
      allow(Time).to receive(:now).and_return(Time.now + 3600)
      expect(manager.locked?(path)).to be(false)
    end

    it "returns false when ancestor lock is depth:zero" do
      manager.acquire(collection_path, scope: :exclusive, depth: :zero)
      expect(manager.locked?(path)).to be(false)
    end
  end

  # ─── prune_expired! ─────────────────────────────────────────────────────────

  describe "#prune_expired!" do
    it "removes expired locks" do
      lock = manager.acquire(path, scope: :exclusive, depth: :zero, timeout: 1)
      allow(Time).to receive(:now).and_return(Time.now + 3600)
      manager.prune_expired!
      expect(manager.locks_for(path)).not_to include(lock)
    end

    it "keeps active locks" do
      lock = manager.acquire(path, scope: :exclusive, depth: :zero, timeout: 3600)
      manager.prune_expired!
      expect(manager.locks_for(path)).to include(lock)
    end

    it "keeps locks with :infinite timeout" do
      lock = manager.acquire(path, scope: :exclusive, depth: :zero, timeout: :infinite)
      allow(Time).to receive(:now).and_return(Time.now + 999_999)
      manager.prune_expired!
      expect(manager.locks_for(path)).to include(lock)
    end
  end

  # ─── Thread safety ──────────────────────────────────────────────────────────

  describe "thread safety" do
    it "survives concurrent acquire calls without corrupting state" do
      paths  = (1..20).map { |i| "/file#{i}.txt" }
      errors = []
      mutex  = Mutex.new

      threads = paths.map do |p|
        Thread.new do
          manager.acquire(p, scope: :exclusive, depth: :zero)
        rescue => e
          mutex.synchronize { errors << e }
        end
      end

      threads.each(&:join)

      expect(errors).to be_empty
      # All 20 paths should now be locked
      paths.each do |p|
        expect(manager.locked?(p)).to be(true)
      end
    end
  end
end
