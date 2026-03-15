# frozen_string_literal: true

require "securerandom"
require "samba_dave/protocol/constants"
require "samba_dave/protocol/header"
require "samba_dave/protocol/transport"
require "samba_dave/protocol/commands/negotiate"

module SambaDave
  # Per-connection state machine.
  #
  # One `Connection` is created per accepted TCP client. It runs a blocking
  # message loop in the caller's thread: reads framed SMB2 messages, parses
  # the header, dispatches to the appropriate command handler, and writes the
  # response back over the socket.
  #
  # State machine:
  #   :initial     — before NEGOTIATE is processed
  #   :negotiated  — dialect agreed; awaiting SESSION_SETUP (Phase 2)
  #
  # Unknown commands always return STATUS_NOT_IMPLEMENTED.
  # A clean EOF or IOError terminates the loop gracefully.
  #
  class Connection
    C = Protocol::Constants

    attr_reader :id

    # @param socket [IO] the TCP client socket (or IO-compatible pipe for tests)
    # @param server [Server] the parent server instance (for server_guid, etc.)
    def initialize(socket, server)
      @socket = socket
      @server = server
      @id     = SecureRandom.uuid
      @state  = :initial
    end

    # Run the connection message loop (blocking).
    #
    # Reads framed SMB2 messages until EOF or an IO error.
    # Each message is dispatched and a response is written back.
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
    #
    # @param raw [String] the raw message bytes (without the 4-byte frame header)
    def handle_message(raw)
      return if raw.nil? || raw.bytesize < 64

      # Check for SMB1 COM_NEGOTIATE (0xFF 'SMB') — handle by ignoring (drop connection)
      # Phase 1: only handle direct SMB2 messages
      if raw[0, 4] == Protocol::Constants::PROTOCOL_ID_SMB1
        handle_smb1_negotiate(raw)
        return
      end

      # Parse the 64-byte SMB2 sync header
      begin
        request_header = Protocol::Header.read(raw[0, 64])
      rescue => e
        # Malformed header — drop the connection
        return
      end

      # Route by command code
      response_body = dispatch(request_header, raw[64..] || "")

      # Build and send the response
      response_header = Protocol::Header.response_for(request_header, status: response_status_for(response_body))
      send_response(response_header, response_body)
    end

    # Dispatch to the correct command handler.
    #
    # Returns the raw response body bytes. For commands we don't implement,
    # returns a minimal error body (nil means use STATUS_NOT_IMPLEMENTED).
    #
    # @param header [Protocol::Header] parsed request header
    # @param body [String] request body bytes (after the header)
    # @return [String, nil] response body bytes, or nil for NOT_IMPLEMENTED
    def dispatch(header, body)
      case header.command
      when C::Commands::NEGOTIATE
        handle_negotiate(body)
      else
        handle_not_implemented(header)
      end
    end

    # Handle SMB2 NEGOTIATE
    def handle_negotiate(body)
      request = Protocol::Commands::NegotiateRequest.read(body)
      @state = :negotiated
      Protocol::Commands::Negotiate.handle(request, server_guid: @server.server_guid)
    rescue => e
      nil  # malformed request — STATUS_NOT_IMPLEMENTED
    end

    # Return a STATUS_NOT_IMPLEMENTED body stub (empty — header carries the status)
    def handle_not_implemented(header)
      nil
    end

    # Handle an SMB1 COM_NEGOTIATE packet (detect and close — Phase 2 will handle properly)
    def handle_smb1_negotiate(raw)
      # For Phase 1, just drop the connection (smbclient with --option="client min protocol=SMB2"
      # will send SMB2 directly). SMB1 downgrade negotiation is a Phase 2 concern.
    end

    # Determine the NT status code from a response body.
    #
    # Convention: `nil` body → STATUS_NOT_IMPLEMENTED.
    # Real bodies carry SUCCESS by default (the handler sets the code in the body).
    def response_status_for(response_body)
      if response_body.nil?
        C::Status::NOT_IMPLEMENTED
      else
        C::Status::SUCCESS
      end
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
