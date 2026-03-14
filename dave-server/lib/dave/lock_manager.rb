require "securerandom"
require_relative "lock_info"
require_relative "errors"

module Dave
  # Thread-safe in-memory store for WebDAV write locks.
  class LockManager
    def initialize
      @locks = {}   # token => LockInfo
      @mutex = Mutex.new
    end

    # Acquire a new lock. Returns a Dave::LockInfo on success.
    # Raises Dave::LockConflictError if a conflicting lock exists.
    def acquire(path, scope:, depth:, owner: nil, timeout: 3600, principal: nil)
      @mutex.synchronize do
        check_conflicts!(path, scope)

        token = "urn:uuid:#{SecureRandom.uuid}"
        lock  = LockInfo.new(
          token:      token,
          path:       path,
          scope:      scope,
          type:       :write,
          depth:      depth,
          owner:      owner,
          timeout:    timeout,
          principal:  principal,
          created_at: Time.now
        )
        @locks[token] = lock
        lock
      end
    end

    # Refresh an existing lock (extend timeout). Returns updated LockInfo.
    # Raises Dave::LockNotFoundError if token not found or lock has expired.
    def refresh(token, timeout:)
      now = Time.now
      @mutex.synchronize do
        lock = @locks[token]
        raise LockNotFoundError, "Lock not found: #{token}" unless lock
        raise LockNotFoundError, "Lock has expired: #{token}" if expired?(lock, now)

        updated = LockInfo.new(
          token:      lock.token,
          path:       lock.path,
          scope:      lock.scope,
          type:       lock.type,
          depth:      lock.depth,
          owner:      lock.owner,
          timeout:    timeout,
          principal:  lock.principal,
          created_at: lock.created_at
        )
        @locks[token] = updated
        updated
      end
    end

    # Release a lock by token. Returns true if found+removed, false if not found.
    def release(token)
      @mutex.synchronize do
        if @locks.key?(token)
          @locks.delete(token)
          true
        else
          false
        end
      end
    end

    # Returns all active (non-expired) locks that apply to path:
    #   - direct locks on the path itself
    #   - depth:infinity locks on ancestor paths
    def locks_for(path)
      now = Time.now
      @mutex.synchronize do
        @locks.values.select { |lock| !expired?(lock, now) && applies_to?(lock, path) }
      end
    end

    # Returns true if path is locked for writing (directly or via ancestor
    # depth:infinity lock). Expired locks are ignored.
    def locked?(path)
      now = Time.now
      @mutex.synchronize do
        @locks.values.any? do |lock|
          !expired?(lock, now) && applies_to?(lock, path)
        end
      end
    end

    # Remove expired locks from the store.
    def prune_expired!
      now = Time.now
      @mutex.synchronize do
        @locks.delete_if { |_token, lock| expired?(lock, now) }
      end
      nil
    end

    private

    # Does this lock apply to +path+ (direct or inherited)?
    def applies_to?(lock, path)
      return true if lock.path == path

      if lock.depth == :infinity
        # A depth:infinity lock on a collection covers all descendants
        ancestor = lock.path
        ancestor = "#{ancestor}/" unless ancestor.end_with?("/")
        path.start_with?(ancestor)
      else
        false
      end
    end

    def expired?(lock, now = Time.now)
      return false if lock.timeout == :infinite

      lock.created_at + lock.timeout < now
    end

    # Check whether acquiring a new lock with +scope+ on +path+ conflicts
    # with any existing active locks. Raises LockConflictError if it does.
    def check_conflicts!(path, scope)
      now = Time.now
      @locks.each_value do |lock|
        next if expired?(lock, now)
        next unless applies_to?(lock, path)

        # Exclusive lock conflicts with ANY existing lock
        # Shared lock conflicts only with an exclusive lock
        if scope == :exclusive || lock.scope == :exclusive
          raise LockConflictError, "A conflicting lock exists on #{path}"
        end
      end
    end
  end
end
