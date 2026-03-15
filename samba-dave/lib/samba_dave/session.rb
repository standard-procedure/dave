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
  end
end
