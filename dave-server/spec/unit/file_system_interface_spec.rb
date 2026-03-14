require "spec_helper"
require "dave/errors"
require "dave/principal"
require "dave/file_system_interface"
require "dave/security_interface"

RSpec.describe Dave::FileSystemInterface do
  let(:implementing_class) do
    Class.new do
      include Dave::FileSystemInterface
    end
  end

  let(:instance) { implementing_class.new }

  describe "method stubs raise NotImplementedError" do
    it "raises for get_resource" do
      expect { instance.get_resource("/foo") }.to raise_error(NotImplementedError)
    end

    it "raises for list_children" do
      expect { instance.list_children("/foo/") }.to raise_error(NotImplementedError)
    end

    it "raises for read_content" do
      expect { instance.read_content("/foo") }.to raise_error(NotImplementedError)
    end

    it "raises for write_content" do
      expect { instance.write_content("/foo", StringIO.new("data")) }.to raise_error(NotImplementedError)
    end

    it "raises for create_collection" do
      expect { instance.create_collection("/foo/") }.to raise_error(NotImplementedError)
    end

    it "raises for delete" do
      expect { instance.delete("/foo") }.to raise_error(NotImplementedError)
    end

    it "raises for copy" do
      expect { instance.copy("/src", "/dst") }.to raise_error(NotImplementedError)
    end

    it "raises for move" do
      expect { instance.move("/src", "/dst") }.to raise_error(NotImplementedError)
    end

    it "raises for get_properties" do
      expect { instance.get_properties("/foo") }.to raise_error(NotImplementedError)
    end

    it "raises for set_properties" do
      expect { instance.set_properties("/foo", {}) }.to raise_error(NotImplementedError)
    end

    it "raises for delete_properties" do
      expect { instance.delete_properties("/foo", []) }.to raise_error(NotImplementedError)
    end

    it "raises for lock" do
      expect { instance.lock("/foo", scope: :exclusive, depth: :infinity) }.to raise_error(NotImplementedError)
    end

    it "raises for unlock" do
      expect { instance.unlock("/foo", "urn:uuid:abc") }.to raise_error(NotImplementedError)
    end

    it "raises for get_lock" do
      expect { instance.get_lock("/foo") }.to raise_error(NotImplementedError)
    end

    it "raises for supports_locking?" do
      expect { instance.supports_locking? }.to raise_error(NotImplementedError)
    end

    it "raises for quota_available_bytes" do
      expect { instance.quota_available_bytes("/foo") }.to raise_error(NotImplementedError)
    end

    it "raises for quota_used_bytes" do
      expect { instance.quota_used_bytes("/foo") }.to raise_error(NotImplementedError)
    end
  end

  describe "exactly 17 method stubs" do
    let(:expected_methods) do
      %i[
        get_resource list_children read_content write_content create_collection
        delete copy move get_properties set_properties delete_properties
        lock unlock get_lock supports_locking? quota_available_bytes quota_used_bytes
      ]
    end

    it "defines all 17 interface methods" do
      expected_methods.each do |method_name|
        expect(implementing_class.instance_methods).to include(method_name)
      end
    end

    it "defines exactly 17 interface methods (no extras)" do
      interface_methods = Dave::FileSystemInterface.instance_methods
      expect(interface_methods.length).to eq(17)
    end
  end
end

RSpec.describe "Dave error hierarchy" do
  it "Dave::Error inherits from StandardError" do
    expect(Dave::Error.ancestors).to include(StandardError)
  end

  it "Dave::NotFoundError inherits from Dave::Error" do
    expect(Dave::NotFoundError.ancestors).to include(Dave::Error)
  end

  it "Dave::AlreadyExistsError inherits from Dave::Error" do
    expect(Dave::AlreadyExistsError.ancestors).to include(Dave::Error)
  end

  it "Dave::NotACollectionError inherits from Dave::Error" do
    expect(Dave::NotACollectionError.ancestors).to include(Dave::Error)
  end

  it "Dave::LockedError inherits from Dave::Error" do
    expect(Dave::LockedError.ancestors).to include(Dave::Error)
  end

  it "Dave::InsufficientStorageError inherits from Dave::Error" do
    expect(Dave::InsufficientStorageError.ancestors).to include(Dave::Error)
  end

  it "Dave::NotFoundError can be raised and rescued as StandardError" do
    expect { raise Dave::NotFoundError, "not found" }.to raise_error(StandardError)
  end
end

RSpec.describe Dave::Principal do
  it "can be constructed with id and display_name" do
    principal = Dave::Principal.new(id: "alice", display_name: "Alice Smith")
    expect(principal.id).to eq("alice")
    expect(principal.display_name).to eq("Alice Smith")
  end

  it "is immutable (frozen)" do
    principal = Dave::Principal.new(id: "bob", display_name: "Bob Jones")
    expect(principal).to be_frozen
  end

  it "supports equality by value" do
    p1 = Dave::Principal.new(id: "alice", display_name: "Alice")
    p2 = Dave::Principal.new(id: "alice", display_name: "Alice")
    expect(p1).to eq(p2)
  end
end

RSpec.describe Dave::LockInfo do
  let(:lock) do
    Dave::LockInfo.new(
      token: "urn:uuid:1234-5678-abcd",
      path: "/foo/bar.txt",
      scope: :exclusive,
      type: :write,
      depth: :infinity,
      owner: "<D:href>http://example.com/~alice/</D:href>",
      timeout: 3600,
      principal: "alice",
      created_at: Time.now
    )
  end

  it "can be constructed with all fields" do
    expect(lock).to be_a(Dave::LockInfo)
  end

  it "exposes token by name" do
    expect(lock.token).to eq("urn:uuid:1234-5678-abcd")
  end

  it "exposes path by name" do
    expect(lock.path).to eq("/foo/bar.txt")
  end

  it "exposes scope by name" do
    expect(lock.scope).to eq(:exclusive)
  end

  it "exposes type by name" do
    expect(lock.type).to eq(:write)
  end

  it "exposes depth by name" do
    expect(lock.depth).to eq(:infinity)
  end

  it "exposes owner by name" do
    expect(lock.owner).to eq("<D:href>http://example.com/~alice/</D:href>")
  end

  it "exposes timeout by name" do
    expect(lock.timeout).to eq(3600)
  end

  it "exposes principal by name" do
    expect(lock.principal).to eq("alice")
  end

  it "exposes created_at by name" do
    expect(lock.created_at).to be_a(Time)
  end

  it "scope can be :exclusive" do
    lock_exclusive = Dave::LockInfo.new(
      token: "urn:uuid:aaa", path: "/x", scope: :exclusive, type: :write,
      depth: :infinity, owner: nil, timeout: :infinite, principal: nil, created_at: Time.now
    )
    expect(lock_exclusive.scope).to eq(:exclusive)
  end

  it "scope can be :shared" do
    lock_shared = Dave::LockInfo.new(
      token: "urn:uuid:bbb", path: "/x", scope: :shared, type: :write,
      depth: :infinity, owner: nil, timeout: :infinite, principal: nil, created_at: Time.now
    )
    expect(lock_shared.scope).to eq(:shared)
  end

  it "depth can be :zero" do
    lock_zero = Dave::LockInfo.new(
      token: "urn:uuid:ccc", path: "/x", scope: :exclusive, type: :write,
      depth: :zero, owner: nil, timeout: 100, principal: nil, created_at: Time.now
    )
    expect(lock_zero.depth).to eq(:zero)
  end

  it "depth can be :infinity" do
    lock_inf = Dave::LockInfo.new(
      token: "urn:uuid:ddd", path: "/x", scope: :exclusive, type: :write,
      depth: :infinity, owner: nil, timeout: 100, principal: nil, created_at: Time.now
    )
    expect(lock_inf.depth).to eq(:infinity)
  end
end

RSpec.describe Dave::SecurityInterface do
  let(:implementing_class) do
    Class.new do
      include Dave::SecurityInterface
    end
  end

  let(:instance) { implementing_class.new }

  it "raises NotImplementedError for authenticate" do
    fake_request = double("request")
    expect { instance.authenticate(fake_request) }.to raise_error(NotImplementedError)
  end

  it "raises NotImplementedError for challenge" do
    expect { instance.challenge }.to raise_error(NotImplementedError)
  end

  it "raises NotImplementedError for authorize" do
    principal = Dave::Principal.new(id: "alice", display_name: "Alice")
    expect { instance.authorize(principal, "/foo", :read) }.to raise_error(NotImplementedError)
  end
end
