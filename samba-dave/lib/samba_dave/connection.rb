# frozen_string_literal: true

require "securerandom"
require "samba_dave/protocol/constants"
require "samba_dave/protocol/header"
require "samba_dave/protocol/transport"
require "samba_dave/protocol/commands/negotiate"
require "samba_dave/protocol/commands/session_setup"
require "samba_dave/protocol/commands/logoff"
require "samba_dave/authenticator"
require "samba_dave/session"

module SambaDave
  # Per-connection state machine.
  #
  # One `Connection` is created per accepted TCP client. It runs a blocking
  # message loop in the caller's thread: reads framed SMB2 messages, parses
  # the header, dispatches to the appropriate command handler, and writes the
  # response back over the socket.
  #
  # ## State machine
  #
  #   :initial     — before NEGOTIATE is processed
  #   :negotiated  — dialect agreed; awaiting SESSION_SETUP
  #   :authenticated — at least one authenticated session exists
  #
  # ## Session Enforcement (Phase 2)
  #
  # Commands other than NEGOTIATE and SESSION_SETUP require an authenticated
  # session (session_id must map to an authenticated Session object). If no
  # such session exists, the server responds with STATUS_USER_SESSION_DELETED.
  #
  # ## Multiple Sessions
  #
  # One connection can have multiple sessions (different users). Sessions are
  # keyed by session_id (from the SMB2 header). SESSION_SETUP creates them;
  # LOGOFF removes them.
  #
  class Connection
    C = Protocol::Constants

    # Commands that are allowed without an authenticated session.
    SESSION_EXEMPT_COMMANDS = [
      C::Commands::NEGOTIATE,
      C::Commands::SESSION_SETUP
    ].freeze

    attr_reader :id

    # @param socket [IO] the TCP client socket (or IO-compatible pipe for tests)
    # @param server [Server] the parent server instance (for server_guid, security_provider)
    def initialize(socket, server)
      @socket          = socket
      @server          = server
      @id              = SecureRandom.uuid
      @state           = :initial
      @sessions        = {}               # session_id (Integer) → Session
      @sessions_mutex  = Mutex.new
      @authenticator   = Authenticator.new(server.security_provider)
      @next_session_id = SecureRandom.random_number(2**31) + 1  # non-zero start
    end

    # Run the connection message loop (blocking).
    def run
      loop do
        raw = Protocol::Transport.read_message(@socket)
        handle_message(raw)
      rescue EOFError
        break
      rescue IOError, Errno::ECONNRESET, Errno::EPIPE
        break
      end
    ensure
      @socket.close rescue nil
    end

    private

    # Dispatch a raw SMB2 message to the appropriate handler.
    def handle_message(raw)
      return if raw.nil? || raw.bytesize < 64

      if raw[0, 4] == Protocol::Constants::PROTOCOL_ID_SMB1
        handle_smb1_negotiate(raw)
        return
      end

      begin
        request_header = Protocol::Header.read(raw[0, 64])
      rescue
        return
      end

      response_result = dispatch(request_header, raw[64..] || "")

      response_status     = response_result[:status]
      response_body       = response_result[:body]
      response_session_id = response_result[:response_session_id]

      response_header = Protocol::Header.response_for(
        request_header,
        status:     response_status,
        session_id: response_session_id
      )
      send_response(response_header, response_body)
    end

    # Dispatch to the correct command handler.
    #
    # Returns { status: Integer, body: String }.
    def dispatch(header, body)
      command    = header.command
      session_id = header.session_id

      # NEGOTIATE and SESSION_SETUP are always allowed (no auth check)
      case command
      when C::Commands::NEGOTIATE
        return handle_negotiate(body)
      when C::Commands::SESSION_SETUP
        return handle_session_setup(body, session_id)
      when C::Commands::LOGOFF
        return handle_logoff(body, session_id)
      end

      # All other commands require an authenticated session
      unless authenticated_session?(session_id)
        return { status: C::Status::USER_SESSION_DELETED, body: "" }
      end

      # Unimplemented commands (future phases)
      { status: C::Status::NOT_IMPLEMENTED, body: "" }
    end

    # Handle SMB2 NEGOTIATE
    def handle_negotiate(body)
      request = Protocol::Commands::NegotiateRequest.read(body)
      @state = :negotiated
      response_body = Protocol::Commands::Negotiate.handle(
        request,
        server_guid: @server.server_guid
      )
      { status: C::Status::SUCCESS, body: response_body }
    rescue
      { status: C::Status::NOT_IMPLEMENTED, body: "" }
    end

    # Handle SMB2 SESSION_SETUP (two rounds).
    #
    # Round 1: session_id from client is 0 (or unknown). Allocate a new
    # session_id, store the pending challenge under it, and return the new
    # session_id in the response header.
    #
    # Round 2: session_id from client is the one we allocated in Round 1.
    # Validate credentials and create/reject the session.
    def handle_session_setup(body, session_id)
      # Determine if this is Round 1 (no pending challenge for the given session_id)
      effective_session_id = if session_id == 0 || !@authenticator.pending_challenge?(session_id)
        # Round 1: allocate a new session_id
        allocate_session_id
      else
        session_id
      end

      result = Protocol::Commands::SessionSetup.handle(
        body,
        session_id:    effective_session_id,
        authenticator: @authenticator,
        sessions:      @sessions
      )

      # Always include the (allocated or reused) session_id in the response header
      result.merge(response_session_id: effective_session_id)
    end

    # Allocate a new unique session_id (monotonically increasing, non-zero).
    def allocate_session_id
      @next_session_id += 1
    end

    # Handle SMB2 LOGOFF
    def handle_logoff(body, session_id)
      Protocol::Commands::Logoff.handle(
        body,
        session_id: session_id,
        sessions:   @sessions
      )
    end

    # Handle an SMB1 COM_NEGOTIATE packet
    def handle_smb1_negotiate(raw)
      # Drop the connection — direct SMB2 only in this phase
    end

    # Check if the given session_id has an authenticated session.
    def authenticated_session?(session_id)
      session = @sessions[session_id]
      session&.authenticated?
    end

    # Serialise and write a response.
    def send_response(header, body)
      message = header.to_binary_s + (body || "")
      Protocol::Transport.write_message(@socket, message)
    rescue IOError, Errno::EPIPE, Errno::ECONNRESET
      # Client disconnected — swallow
    end
  end
end
