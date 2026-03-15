# frozen_string_literal: true

require "spec_helper"
require "socket"
require "samba_dave/server"
require "samba_dave/structured_logger"
require "samba_dave/protocol/constants"
require "samba_dave/protocol/header"
require "samba_dave/protocol/transport"
require "samba_dave/protocol/commands/negotiate"

RSpec.describe SambaDave::Server do
  let(:filesystem) { instance_double("Dave::FileSystemInterface") }

  # Find a free port for testing
  def free_port
    s = TCPServer.new("127.0.0.1", 0)
    port = s.addr[1]
    s.close
    port
  end

  describe "#initialize" do
    it "creates a server with required parameters" do
      server = described_class.new(filesystem: filesystem, logger: SambaDave::StructuredLogger.new(File::NULL))

      expect(server.share_name).to eq("share")
      expect(server.port).to eq(445)
      expect(server.server_guid).to be_a(String)
      expect(server.server_guid.bytesize).to eq(16)
    end

    it "accepts custom share name and port" do
      server = described_class.new(
        filesystem: filesystem,
        share_name: "documents",
        port: 4450
      )

      expect(server.share_name).to eq("documents")
      expect(server.port).to eq(4450)
    end

    it "generates a unique server GUID" do
      server1 = described_class.new(filesystem: filesystem)
      server2 = described_class.new(filesystem: filesystem)

      expect(server1.server_guid).not_to eq(server2.server_guid)
    end
  end

  describe "#start and #stop" do
    let(:null_logger) { SambaDave::StructuredLogger.new(File::NULL) }

    it "starts, accepts a connection, handles a NEGOTIATE, and stops cleanly" do
      port = free_port
      server = described_class.new(filesystem: filesystem, port: port, logger: null_logger)

      server_thread = Thread.new { server.start }
      sleep 0.05  # Allow the server to bind and enter accept loop

      # Connect as a client and send a NEGOTIATE request
      client = TCPSocket.new("127.0.0.1", port)

      header = SambaDave::Protocol::Header.new(
        command: SambaDave::Protocol::Constants::Commands::NEGOTIATE,
        message_id: 1
      )
      body = [36, 1, 0, 0, 0].pack("S<S<S<S<L<") +
             "\x00" * 16 +
             [0].pack("Q<") +
             [0x0202].pack("S<")
      request_frame = SambaDave::Protocol::Transport.frame(header.to_binary_s + body)
      client.write(request_frame)
      client.flush

      # Read the NEGOTIATE response
      raw_msg = SambaDave::Protocol::Transport.read_message(client)
      resp_header = SambaDave::Protocol::Header.read(raw_msg[0, 64])

      expect(resp_header.command).to eq(SambaDave::Protocol::Constants::Commands::NEGOTIATE)
      expect(resp_header.status).to eq(SambaDave::Protocol::Constants::Status::SUCCESS)
      expect(resp_header.flags & SambaDave::Protocol::Constants::Flags::SERVER_TO_REDIR).to eq(1)

      resp_body = SambaDave::Protocol::Commands::NegotiateResponse.read(raw_msg[64..])
      expect(resp_body.dialect_revision).to eq(0x0202)
      expect(resp_body.server_guid).to eq(server.server_guid)

      client.close
      server.stop
      server_thread.join(2)
    end

    it "can stop a running server" do
      port = free_port
      server = described_class.new(filesystem: filesystem, port: port, logger: null_logger)

      server_thread = Thread.new { server.start }
      sleep 0.05

      expect { server.stop }.not_to raise_error
      server_thread.join(2)

      # After stop, port should be free again
      expect { TCPSocket.new("127.0.0.1", port) }.to raise_error(Errno::ECONNREFUSED)
    end

    it "handles multiple concurrent connections" do
      port = free_port
      server = described_class.new(filesystem: filesystem, port: port, logger: null_logger)

      server_thread = Thread.new { server.start }
      sleep 0.05

      clients = 3.times.map { TCPSocket.new("127.0.0.1", port) }

      clients.each do |client|
        header = SambaDave::Protocol::Header.new(
          command: SambaDave::Protocol::Constants::Commands::NEGOTIATE,
          message_id: 1
        )
        body = [36, 1, 0, 0, 0].pack("S<S<S<S<L<") + "\x00" * 16 + [0].pack("Q<") + [0x0202].pack("S<")
        client.write(SambaDave::Protocol::Transport.frame(header.to_binary_s + body))
        client.flush
      end

      responses = clients.map do |client|
        raw = SambaDave::Protocol::Transport.read_message(client)
        SambaDave::Protocol::Header.read(raw[0, 64])
      end

      responses.each do |hdr|
        expect(hdr.status).to eq(SambaDave::Protocol::Constants::Status::SUCCESS)
      end

      clients.each(&:close)
      server.stop
      server_thread.join(2)
    end
  end
end
