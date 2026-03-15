# frozen_string_literal: true

require "socket"
require "securerandom"
require "samba_dave/connection"

module SambaDave
  # SMB2 file server that uses Dave::FileSystemInterface providers.
  #
  # Listens on a TCP port (default 445) and serves files via the SMB2 protocol.
  # Uses the same pluggable provider architecture as Dave::Server (WebDAV).
  #
  # @example Basic usage
  #   server = SambaDave::Server.new(
  #     filesystem: Dave::FileSystemProvider.new(root: "/var/shares"),
  #     share_name: "files",
  #     port: 445
  #   )
  #   server.start
  #
  # @example With authentication
  #   server = SambaDave::Server.new(
  #     filesystem: my_provider,
  #     security: my_security_provider,
  #     share_name: "documents",
  #     port: 445
  #   )
  #   server.start
  #
  class Server
    VERSION = "0.1.0"

    attr_reader :server_guid, :share_name, :port, :filesystem

    # @param filesystem [Dave::FileSystemInterface] file operations provider
    # @param security [Dave::SecurityInterface, nil] authentication provider (nil = no auth)
    # @param share_name [String] name of the SMB share
    # @param port [Integer] TCP port to listen on (445 = standard, 4450 = development)
    def initialize(filesystem:, share_name: "share", security: nil, port: 445)
      @filesystem  = filesystem
      @security    = security
      @share_name  = share_name
      @port        = port
      @server_guid = SecureRandom.bytes(16)
      @running     = false
      @connections = {}
      @connections_mutex = Mutex.new
    end

    # Start the server (blocking).
    # Listens for TCP connections and spawns a thread per client.
    def start
      raise "Server already running" if @running

      @running    = true
      @tcp_server = TCPServer.new("0.0.0.0", @port)

      while @running
        begin
          client = @tcp_server.accept
          Thread.new(client) { |sock| handle_connection(sock) }
        rescue IOError, Errno::EBADF, Errno::EINVAL
          break
        end
      end
    end

    # Stop the server and close all active connections.
    def stop
      @running = false
      @tcp_server&.close
    end

    private

    def handle_connection(socket)
      connection = Connection.new(socket, self)
      @connections_mutex.synchronize { @connections[connection.id] = connection }
      connection.run  # blocking — reads messages until disconnect
    ensure
      @connections_mutex.synchronize { @connections.delete(connection&.id) }
      socket.close rescue nil
    end
  end
end
