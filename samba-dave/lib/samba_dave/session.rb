# frozen_string_literal: true

module SambaDave
  # Per-session state for an authenticated SMB2 client.
  #
  # One Connection can have multiple Sessions (different users). Each Session
  # is identified by a SessionId assigned by the server during SESSION_SETUP.
  #
  # State transitions:
  #   unauthenticated → authenticated (after successful SESSION_SETUP Round 2)
  #
  # ## Credit tracking (SMB 2.1)
  #
  # The session tracks how many credits the client currently holds.
  # Credits are added when granted in responses and consumed per request.
  #
  # ## Thread safety
  #
  # The tree_connects hash and tree_id counter are protected by a Mutex so that
  # concurrent access (e.g. from audit threads) cannot corrupt state.
  # The credit counter is also mutex-protected.
  #
  class Session
    attr_reader :session_id, :user_identity, :signing_key
    attr_accessor :session_key

    # @param session_id [Integer] 8-byte session identifier
    def initialize(session_id:)
      @session_id     = session_id
      @user_identity  = nil
      @session_key    = nil
      @signing_key    = nil
      @authenticated  = false
      @tree_connects  = {}   # tree_id (Integer) → TreeConnect
      @next_tree_id   = 1
      @credits        = 0
      @mutex          = Mutex.new
    end

    # Mark session as authenticated with a user identity.
    #
    # @param identity [Object] user identity returned by the SecurityProvider
    # @return [self]
    def authenticate!(identity)
      @user_identity = identity
      @authenticated = true
      self
    end

    # @return [Boolean] true if SESSION_SETUP has completed successfully
    def authenticated?
      @authenticated
    end

    # Derive and cache the signing key from the session key.
    # SigningKey = HMAC-SHA256(SessionKey, "SMBSigningKey\x00")
    # Called once after session_key is set.
    #
    # @param key [String] 16-byte NTLM session base key
    def set_session_key(key)
      require "openssl"
      @session_key = key
      @signing_key = OpenSSL::HMAC.digest("SHA256", key, "SMBSigningKey\x00") if key
    end

    # ── Credit Management ────────────────────────────────────────────────────

    # @return [Integer] current credit balance
    def credits
      @mutex.synchronize { @credits }
    end

    # Add granted credits to the session balance.
    #
    # @param amount [Integer] number of credits to add
    def add_credits(amount)
      @mutex.synchronize { @credits += amount }
    end

    # Consume credits for a request.
    #
    # @param amount [Integer] number of credits to consume
    def consume_credits(amount)
      @mutex.synchronize { @credits -= amount }
    end

    # ── Tree Connect Management ──────────────────────────────────────────────

    # Allocate a new unique TreeId (monotonically increasing, non-zero, 32-bit).
    # Thread-safe.
    #
    # @return [Integer]
    def allocate_tree_id
      @mutex.synchronize do
        id = @next_tree_id
        @next_tree_id = (@next_tree_id % 0xFFFFFFFE) + 1
        id
      end
    end

    # Register a new tree connect under its tree_id.
    # Thread-safe.
    #
    # @param tree_connect [TreeConnect]
    def add_tree_connect(tree_connect)
      @mutex.synchronize { @tree_connects[tree_connect.tree_id] = tree_connect }
    end

    # Look up an active tree connect by tree_id.
    # Thread-safe.
    #
    # @param tree_id [Integer]
    # @return [TreeConnect, nil]
    def find_tree_connect(tree_id)
      @mutex.synchronize { @tree_connects[tree_id] }
    end

    # Remove a tree connect. Silently ignores unknown tree_ids.
    # Thread-safe.
    #
    # @param tree_id [Integer]
    def remove_tree_connect(tree_id)
      @mutex.synchronize { @tree_connects.delete(tree_id) }
    end
  end
end
