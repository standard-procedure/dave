# frozen_string_literal: true

require "samba_dave/protocol/constants"
require "samba_dave/crypto/kdf"

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
    # SMB 3.0/3.0.2 signing-key derivation constants (SP800-108 KDF inputs).
    SMB3_SIGNING_LABEL   = "SMB2AESCMAC\x00".b.freeze
    SMB3_SIGNING_CONTEXT = "SmbSign\x00".b.freeze

    attr_reader :session_id, :user_identity, :signing_key
    # :hmac_sha256 (SMB 2.x) or :aes_cmac (SMB 3.x) — the MAC for this session.
    attr_reader :signing_algorithm
    attr_accessor :session_key
    # Whether the client negotiated SMB2_NEGOTIATE_SIGNING_REQUIRED for this
    # session; when true, the server rejects unsigned requests on it.
    attr_writer :signing_required

    # @param session_id [Integer] 8-byte session identifier
    def initialize(session_id:)
      @session_id       = session_id
      @user_identity    = nil
      @session_key       = nil
      @signing_key       = nil
      @signing_algorithm = nil
      @signing_required = false
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

    # @return [Boolean] true if the client required signing for this session
    def signing_required?
      @signing_required
    end

    # Install the SMB2/3 session key and derive the signing key + MAC algorithm
    # for the negotiated dialect.
    #
    # The SessionKey is the first 16 bytes of the NTLM ExportedSessionKey,
    # right-padded with zeroes if shorter. From it:
    #
    # - SMB 2.0.2/2.1: SigningKey == SessionKey (no KDF); MAC = HMAC-SHA256.
    # - SMB 3.0/3.0.2: SigningKey = SMB3KDF(SessionKey, "SMB2AESCMAC\0",
    #   "SmbSign\0"); MAC = AES-128-CMAC.
    #
    # (SMB 3.1.1 uses a different KDF context — the pre-auth integrity hash —
    # and is handled when that dialect is negotiated.)
    #
    # @param key [String, nil] the NTLM ExportedSessionKey (16 bytes)
    # @param dialect [Integer] the negotiated SMB dialect revision
    def set_session_key(key, dialect: Protocol::Constants::Dialects::SMB2_1)
      @session_key = key
      if key.nil?
        @signing_key = nil
        @signing_algorithm = nil
        return
      end

      bytes = key.b
      padded = bytes.bytesize >= 16 ? bytes.byteslice(0, 16) : bytes + ("\x00".b * (16 - bytes.bytesize))

      if dialect >= Protocol::Constants::Dialects::SMB3_0
        @signing_key = Crypto::KDF.sp800_108_counter(key: padded, label: SMB3_SIGNING_LABEL, context: SMB3_SIGNING_CONTEXT)
        @signing_algorithm = :aes_cmac
      else
        @signing_key = padded
        @signing_algorithm = :hmac_sha256
      end
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
