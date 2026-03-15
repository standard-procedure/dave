# frozen_string_literal: true

require "spec_helper"
require "socket"
require "samba_dave/connection"
require "samba_dave/protocol/constants"
require "samba_dave/protocol/header"
require "samba_dave/protocol/transport"
require "samba_dave/protocol/commands/negotiate"

RSpec.describe SambaDave::Connection do
  let(:server_guid) { "B" * 16 }
  let(:server) { instance_double("SambaDave::Server", server_guid: server_guid) }

  # Run the connection in the current thread using a UNIXSocket pair.
  # Writes `request_frame` bytes to the client side, signals EOF (SHUT_WR),
  # then runs the connection and returns all bytes received by the client.
  def run_with_frame(request_frame)
    client_sock, server_sock = UNIXSocket.pair

    client_sock.write(request_frame)
    client_sock.shutdown(Socket::SHUT_WR)  # EOF to server connection

    conn = described_class.new(server_sock, server)
    conn.run  # blocking; returns when client EOF causes our loop to break

    client_sock.shutdown(Socket::SHUT_RD)
    # server_sock is already closed by conn.run's ensure block
    client_sock.read.tap { client_sock.close rescue nil }
  end

  # Build a framed NEGOTIATE request
  def negotiate_request_frame(dialects: [0x0202], message_id: 1, security_mode: 0)
    header = SambaDave::Protocol::Header.new(
      command: SambaDave::Protocol::Constants::Commands::NEGOTIATE,
      message_id: message_id
    )
    body = [
      36, dialects.size, security_mode, 0, 0
    ].pack("S<S<S<S<L<") +
      "\x00" * 16 +
      [0].pack("Q<") +
      dialects.pack("S<*")

    SambaDave::Protocol::Transport.frame(header.to_binary_s + body)
  end

  # Build a framed message with given command and empty body
  def build_smb2_frame(command:, message_id: 1)
    header = SambaDave::Protocol::Header.new(command: command, message_id: message_id)
    SambaDave::Protocol::Transport.frame(header.to_binary_s)
  end

  describe "#initialize" do
    it "assigns a unique connection ID" do
      client1, server1 = UNIXSocket.pair
      client2, server2 = UNIXSocket.pair
      conn1 = described_class.new(server1, server)
      conn2 = described_class.new(server2, server)
      expect(conn1.id).not_to eq(conn2.id)
      [client1, server1, client2, server2].each { |s| s.close rescue nil }
    end
  end

  describe "#run — NEGOTIATE handling" do
    it "responds to a NEGOTIATE request with a framed SMB2 response" do
      response_data = run_with_frame(negotiate_request_frame)
      expect(response_data.bytesize).to be > 4
    end

    it "returns an SMB2 NEGOTIATE response with correct header fields" do
      response_data = run_with_frame(negotiate_request_frame)

      response_io = StringIO.new(response_data)
      raw_msg = SambaDave::Protocol::Transport.read_message(response_io)

      resp_header = SambaDave::Protocol::Header.read(raw_msg[0, 64])
      expect(resp_header.protocol_id).to eq("\xFESMB".b)
      expect(resp_header.command).to eq(SambaDave::Protocol::Constants::Commands::NEGOTIATE)
      expect(resp_header.status).to eq(SambaDave::Protocol::Constants::Status::SUCCESS)
      expect(resp_header.flags & SambaDave::Protocol::Constants::Flags::SERVER_TO_REDIR).to eq(1)
    end

    it "echoes the message_id from the request" do
      response_data = run_with_frame(negotiate_request_frame(message_id: 42))

      response_io = StringIO.new(response_data)
      raw_msg = SambaDave::Protocol::Transport.read_message(response_io)
      resp_header = SambaDave::Protocol::Header.read(raw_msg[0, 64])

      expect(resp_header.message_id).to eq(42)
    end

    it "selects SMB 2.0.2 dialect in the response body" do
      response_data = run_with_frame(negotiate_request_frame(dialects: [0x0202, 0x0210, 0x0302]))

      response_io = StringIO.new(response_data)
      raw_msg = SambaDave::Protocol::Transport.read_message(response_io)
      body = raw_msg[64..]

      resp_body = SambaDave::Protocol::Commands::NegotiateResponse.read(body)
      expect(resp_body.dialect_revision).to eq(0x0202)
    end

    it "includes a security buffer (SPNEGO token) in the response" do
      response_data = run_with_frame(negotiate_request_frame)

      response_io = StringIO.new(response_data)
      raw_msg = SambaDave::Protocol::Transport.read_message(response_io)
      body = raw_msg[64..]

      resp_body = SambaDave::Protocol::Commands::NegotiateResponse.read(body)
      expect(resp_body.security_buffer_length).to be > 0
    end
  end

  describe "#run — unknown command handling" do
    it "returns STATUS_NOT_IMPLEMENTED for unknown commands" do
      frame = build_smb2_frame(command: SambaDave::Protocol::Constants::Commands::READ)
      response_data = run_with_frame(frame)

      response_io = StringIO.new(response_data)
      raw_msg = SambaDave::Protocol::Transport.read_message(response_io)
      resp_header = SambaDave::Protocol::Header.read(raw_msg[0, 64])

      expect(resp_header.status).to eq(SambaDave::Protocol::Constants::Status::NOT_IMPLEMENTED)
    end

    it "handles multiple messages in sequence" do
      # First: unknown, second: negotiate
      frame1 = build_smb2_frame(command: SambaDave::Protocol::Constants::Commands::ECHO)
      frame2 = negotiate_request_frame(message_id: 2)
      response_data = run_with_frame(frame1 + frame2)

      response_io = StringIO.new(response_data)

      msg1 = SambaDave::Protocol::Transport.read_message(response_io)
      hdr1 = SambaDave::Protocol::Header.read(msg1[0, 64])
      expect(hdr1.status).to eq(SambaDave::Protocol::Constants::Status::NOT_IMPLEMENTED)

      msg2 = SambaDave::Protocol::Transport.read_message(response_io)
      hdr2 = SambaDave::Protocol::Header.read(msg2[0, 64])
      expect(hdr2.status).to eq(SambaDave::Protocol::Constants::Status::SUCCESS)
      expect(hdr2.message_id).to eq(2)
    end
  end
end
