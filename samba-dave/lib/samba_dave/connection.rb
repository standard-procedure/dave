# frozen_string_literal: true

require "securerandom"
require "samba_dave/protocol/constants"
require "samba_dave/protocol/header"
require "samba_dave/protocol/transport"
require "samba_dave/protocol/commands/negotiate"
require "samba_dave/protocol/commands/session_setup"
require "samba_dave/protocol/commands/logoff"
require "samba_dave/protocol/commands/echo"
require "samba_dave/protocol/commands/tree_connect"
require "samba_dave/protocol/commands/create"
require "samba_dave/protocol/commands/close"
require "samba_dave/protocol/commands/query_info"
require "samba_dave/protocol/commands/query_directory"
require "samba_dave/protocol/commands/read"
require "samba_dave/protocol/commands/write"
require "samba_dave/protocol/commands/flush"
require "samba_dave/protocol/commands/cancel"
require "samba_dave/protocol/commands/set_info"
require "samba_dave/protocol/commands/ioctl"
require "samba_dave/protocol/commands/lock"
require "samba_dave/protocol/commands/change_notify"
require "samba_dave/authenticator"
require "samba_dave/session"
require "samba_dave/tree_connect"
require "samba_dave/open_file"
require "samba_dave/open_file_table"

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
      @open_file_table = OpenFileTable.new  # connection-scoped handle table
      @logger          = server.logger    # may be nil (no logging)
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

      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      response_result = begin
        dispatch(request_header, raw[64..] || "")
      rescue => e
        # Truncated/malformed body: return INVALID_PARAMETER rather than crashing
        { status: C::Status::INVALID_PARAMETER, body: "" }
      end
      duration_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time) * 1000).round(2)

      # CANCEL (and future async ops) signal that no response should be sent.
      return if response_result[:skip_response]

      log_command(request_header.command, request_header.session_id,
                  response_result[:status], duration_ms)

      response_status     = response_result[:status]
      response_body       = response_result[:body]
      response_session_id = response_result[:response_session_id]
      response_tree_id    = response_result[:response_tree_id]

      command_hint = response_result[:command_hint]
      response_header = Protocol::Header.response_for(
        request_header,
        status:       response_status,
        session_id:   response_session_id,
        tree_id:      response_tree_id,
        command_hint: command_hint
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

      # Return NOT_IMPLEMENTED for completely unknown command codes before
      # applying session authentication checks. This matches the SMB2 spec:
      # unrecognized commands are rejected regardless of session state.
      unless known_command?(command)
        return { status: C::Status::NOT_IMPLEMENTED, body: "" }
      end

      # All other commands require an authenticated session
      unless authenticated_session?(session_id)
        return { status: C::Status::USER_SESSION_DELETED, body: "" }
      end

      session = @sessions[session_id]

      # Phase 3 commands — tree connect, file operations, echo
      case command
      when C::Commands::ECHO
        return handle_echo(body)
      when C::Commands::TREE_CONNECT
        return handle_tree_connect(body, session: session)
      when C::Commands::TREE_DISCONNECT
        return handle_tree_disconnect(body, session: session, tree_id: header.tree_id)
      when C::Commands::CREATE
        tree_connect = session.find_tree_connect(header.tree_id)
        return { status: C::Status::NETWORK_NAME_DELETED, body: "" } unless tree_connect
        return handle_create(body, tree_connect: tree_connect)
      when C::Commands::CLOSE
        return handle_close(body)
      when C::Commands::QUERY_INFO
        return handle_query_info(body)
      when C::Commands::QUERY_DIRECTORY
        return handle_query_directory(body)

      # Phase 4 commands
      when C::Commands::READ
        return handle_read(body)
      when C::Commands::WRITE
        return handle_write(body)
      when C::Commands::FLUSH
        return handle_flush(body)
      when C::Commands::CANCEL
        return handle_cancel(body)
      when C::Commands::SET_INFO
        return handle_set_info(body)

      # Phase 5 commands
      when C::Commands::IOCTL
        return handle_ioctl(body)
      when C::Commands::LOCK
        return handle_lock(body)
      when C::Commands::CHANGE_NOTIFY
        return handle_change_notify(body)
      end

      # Known but not-yet-dispatched commands (shouldn't reach here)
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
      { status: C::Status::SUCCESS, body: response_body, command_hint: :negotiate }
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

    # Handle SMB2 ECHO
    def handle_echo(body)
      Protocol::Commands::Echo.handle(body)
    end

    # Handle SMB2 TREE_CONNECT
    def handle_tree_connect(body, session:)
      Protocol::Commands::TreeConnectCmd.handle(
        body,
        session: session,
        server:  @server
      )
    end

    # Handle SMB2 TREE_DISCONNECT
    def handle_tree_disconnect(body, session:, tree_id:)
      Protocol::Commands::TreeDisconnectCmd.handle(
        body,
        session:  session,
        tree_id:  tree_id
      )
    end

    # Handle SMB2 CREATE
    def handle_create(body, tree_connect:)
      Protocol::Commands::Create.handle(
        body,
        tree_connect:    tree_connect,
        open_file_table: @open_file_table
      )
    end

    # Handle SMB2 CLOSE
    def handle_close(body)
      Protocol::Commands::Close.handle(
        body,
        open_file_table: @open_file_table
      )
    end

    # Handle SMB2 QUERY_INFO
    def handle_query_info(body)
      Protocol::Commands::QueryInfo.handle(
        body,
        open_file_table: @open_file_table
      )
    end

    # Handle SMB2 QUERY_DIRECTORY
    def handle_query_directory(body)
      Protocol::Commands::QueryDirectory.handle(
        body,
        open_file_table: @open_file_table
      )
    end

    # Handle SMB2 READ
    def handle_read(body)
      Protocol::Commands::Read.handle(
        body,
        open_file_table: @open_file_table
      )
    end

    # Handle SMB2 WRITE
    def handle_write(body)
      Protocol::Commands::Write.handle(
        body,
        open_file_table: @open_file_table
      )
    end

    # Handle SMB2 FLUSH
    def handle_flush(body)
      Protocol::Commands::Flush.handle(
        body,
        open_file_table: @open_file_table
      )
    end

    # Handle SMB2 CANCEL (no response sent)
    def handle_cancel(body)
      Protocol::Commands::Cancel.handle(body)
    end

    # Handle SMB2 SET_INFO
    def handle_set_info(body)
      Protocol::Commands::SetInfo.handle(
        body,
        open_file_table: @open_file_table
      )
    end

    # Handle SMB2 IOCTL (Phase 5)
    def handle_ioctl(body)
      Protocol::Commands::Ioctl.handle(
        body,
        server_guid: @server.server_guid
      )
    end

    # Handle SMB2 LOCK (Phase 5 stub)
    def handle_lock(body)
      Protocol::Commands::Lock.handle(body)
    end

    # Handle SMB2 CHANGE_NOTIFY (Phase 5 stub)
    def handle_change_notify(body)
      Protocol::Commands::ChangeNotify.handle(body)
    end

    # Returns true if the command code is a recognized SMB2 command.
    # Unrecognized command codes get STATUS_NOT_IMPLEMENTED before session check.
    def known_command?(command)
      command <= C::Commands::OPLOCK_BREAK
    end

    # Emit a structured log entry for a completed SMB2 command.
    # Uses INFO for normal operations, WARN for auth failures, ERROR for others.
    def log_command(command, session_id, status, duration_ms)
      return unless @logger

      command_name = COMMAND_NAMES[command] || "CMD_#{command.to_s(16).upcase}"

      if status == C::Status::LOGON_FAILURE
        @logger.warn(command_name, session_id: session_id, status: status, duration_ms: duration_ms)
      elsif status != C::Status::SUCCESS && status != C::Status::MORE_PROCESSING_REQUIRED &&
            status != C::Status::NO_MORE_FILES && status != C::Status::BUFFER_OVERFLOW
        @logger.error(command_name, session_id: session_id, status: status, duration_ms: duration_ms)
      else
        @logger.info(command_name, session_id: session_id, status: status, duration_ms: duration_ms)
      end
    end

    # Mapping from command code to human-readable name (for logging)
    COMMAND_NAMES = {
      C::Commands::NEGOTIATE       => "NEGOTIATE",
      C::Commands::SESSION_SETUP   => "SESSION_SETUP",
      C::Commands::LOGOFF          => "LOGOFF",
      C::Commands::TREE_CONNECT    => "TREE_CONNECT",
      C::Commands::TREE_DISCONNECT => "TREE_DISCONNECT",
      C::Commands::CREATE          => "CREATE",
      C::Commands::CLOSE           => "CLOSE",
      C::Commands::FLUSH           => "FLUSH",
      C::Commands::READ            => "READ",
      C::Commands::WRITE           => "WRITE",
      C::Commands::LOCK            => "LOCK",
      C::Commands::IOCTL           => "IOCTL",
      C::Commands::CANCEL          => "CANCEL",
      C::Commands::ECHO            => "ECHO",
      C::Commands::QUERY_DIRECTORY => "QUERY_DIRECTORY",
      C::Commands::CHANGE_NOTIFY   => "CHANGE_NOTIFY",
      C::Commands::QUERY_INFO      => "QUERY_INFO",
      C::Commands::SET_INFO        => "SET_INFO",
      C::Commands::OPLOCK_BREAK    => "OPLOCK_BREAK"
    }.freeze

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
