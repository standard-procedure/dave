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
  class Session
    attr_reader :session_id, :user_identity
    attr_accessor :session_key

    # @param session_id [Integer] 8-byte session identifier
    def initialize(session_id:)
      @session_id     = session_id
      @user_identity  = nil
      @session_key    = nil
      @authenticated  = false
      @tree_connects  = {}  # tree_id (Integer) → TreeConnect
      @next_tree_id   = 1
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

    # ── Tree Connect Management ──────────────────────────────────────────────

    # Allocate a new unique TreeId (monotonically increasing, non-zero, 32-bit).
    #
    # @return [Integer]
    def allocate_tree_id
      id = @next_tree_id
      @next_tree_id = (@next_tree_id % 0xFFFFFFFE) + 1
      id
    end

    # Register a new tree connect under its tree_id.
    #
    # @param tree_connect [TreeConnect]
    def add_tree_connect(tree_connect)
      @tree_connects[tree_connect.tree_id] = tree_connect
    end

    # Look up an active tree connect by tree_id.
    #
    # @param tree_id [Integer]
    # @return [TreeConnect, nil]
    def find_tree_connect(tree_id)
      @tree_connects[tree_id]
    end

    # Remove a tree connect. Silently ignores unknown tree_ids.
    #
    # @param tree_id [Integer]
    def remove_tree_connect(tree_id)
      @tree_connects.delete(tree_id)
    end
  end
end
