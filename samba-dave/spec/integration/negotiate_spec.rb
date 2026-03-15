# frozen_string_literal: true

# Integration test: connects via real TCP socket and exercises the full
# request/response path through SambaDave::Server.
#
# This is the Ruby equivalent of:
#   smbclient -L //localhost -p 4450 --option="client min protocol=SMB2"
#
# It validates that:
#   1. The server accepts a TCP connection on the configured port
#   2. A framed SMB2 NEGOTIATE request returns a valid NEGOTIATE response
#   3. The selected dialect is SMB 2.0.2
#   4. The response contains a SPNEGO security buffer
#   5. The server_guid matches the one returned by SambaDave::Server
#
# A real smbclient would continue to SESSION_SETUP next; this test stops
# after NEGOTIATE (Phase 2 will extend the integration test for auth).
#
# Run tag: :integration (excluded from fast unit tests by default)

require "spec_helper"
require "socket"
require "samba_dave/server"
require "samba_dave/protocol/constants"
require "samba_dave/protocol/header"
require "samba_dave/protocol/transport"
require "samba_dave/protocol/commands/negotiate"

RSpec.describe "SMB2 NEGOTIATE integration", :integration do
  let(:port) { 4450 }
  let(:filesystem) { instance_double("Dave::FileSystemInterface") }

  before(:each) do
    @server = SambaDave::Server.new(
      filesystem: filesystem,
      share_name: "test",
      port: port
    )
    @server_thread = Thread.new { @server.start }
    sleep 0.1  # wait for server to bind
  end

  after(:each) do
    @server.stop
    @server_thread.join(2)
  end

  def send_negotiate_request(socket, dialects: [0x0202, 0x0210], message_id: 1)
    header = SambaDave::Protocol::Header.new(
      command: SambaDave::Protocol::Constants::Commands::NEGOTIATE,
      message_id: message_id
    )
    body = [36, dialects.size, 0x0001, 0, 0].pack("S<S<S<S<L<") +
           SecureRandom.bytes(16) +          # client_guid
           [0].pack("Q<") +                  # client_start_time
           dialects.pack("S<*")
    SambaDave::Protocol::Transport.frame(header.to_binary_s + body)
  end

  it "responds to SMB2 NEGOTIATE with a valid NEGOTIATE response" do
    socket = TCPSocket.new("127.0.0.1", port)
    socket.write(send_negotiate_request(socket))
    socket.flush

    raw = SambaDave::Protocol::Transport.read_message(socket)
    socket.close

    # Must have header + body
    expect(raw.bytesize).to be >= 64 + 64  # header + fixed NEGOTIATE body

    # Parse header
    hdr = SambaDave::Protocol::Header.read(raw[0, 64])
    expect(hdr.protocol_id).to eq("\xFESMB".b)
    expect(hdr.command).to eq(SambaDave::Protocol::Constants::Commands::NEGOTIATE)
    expect(hdr.status).to eq(SambaDave::Protocol::Constants::Status::SUCCESS)
    expect(hdr.flags & SambaDave::Protocol::Constants::Flags::SERVER_TO_REDIR).to eq(1)
    expect(hdr.structure_size).to eq(64)
    expect(hdr.message_id).to eq(1)

    # Parse NEGOTIATE response body
    body = SambaDave::Protocol::Commands::NegotiateResponse.read(raw[64..])
    expect(body.structure_size).to eq(65)
    expect(body.dialect_revision).to eq(SambaDave::Protocol::Constants::Dialects::SMB2_0_2)
    expect(body.security_mode & SambaDave::Protocol::Constants::SecurityMode::SIGNING_ENABLED).to eq(1)
    expect(body.server_guid).to eq(@server.server_guid)
    expect(body.max_transact_size).to eq(8_388_608)
    expect(body.max_read_size).to eq(8_388_608)
    expect(body.max_write_size).to eq(8_388_608)
    expect(body.system_time).to be > 0
    expect(body.security_buffer_offset).to eq(128)
    expect(body.security_buffer_length).to be > 0
    expect(body.security_buffer.bytesize).to eq(body.security_buffer_length)
  end

  it "SPNEGO token starts with APPLICATION [0] tag (0x60) — valid GSS-API token" do
    socket = TCPSocket.new("127.0.0.1", port)
    socket.write(send_negotiate_request(socket))
    socket.flush

    raw = SambaDave::Protocol::Transport.read_message(socket)
    socket.close

    body = SambaDave::Protocol::Commands::NegotiateResponse.read(raw[64..])
    spnego_token = body.security_buffer
    expect(spnego_token[0].ord).to eq(0x60)  # APPLICATION [0] tag
  end

  it "SPNEGO token contains NTLMSSP OID (1.3.6.1.4.1.311.2.2.10)" do
    socket = TCPSocket.new("127.0.0.1", port)
    socket.write(send_negotiate_request(socket))
    socket.flush

    raw = SambaDave::Protocol::Transport.read_message(socket)
    socket.close

    body = SambaDave::Protocol::Commands::NegotiateResponse.read(raw[64..])
    ntlmssp_oid = "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a".b
    expect(body.security_buffer).to include(ntlmssp_oid)
  end

  it "handles multiple sequential connections" do
    3.times do |i|
      socket = TCPSocket.new("127.0.0.1", port)
      socket.write(send_negotiate_request(socket, message_id: i + 1))
      socket.flush
      raw = SambaDave::Protocol::Transport.read_message(socket)
      socket.close

      hdr = SambaDave::Protocol::Header.read(raw[0, 64])
      expect(hdr.status).to eq(SambaDave::Protocol::Constants::Status::SUCCESS)
      expect(hdr.message_id).to eq(i + 1)
    end
  end

  it "handles STATUS_NOT_IMPLEMENTED for SESSION_SETUP before full auth" do
    socket = TCPSocket.new("127.0.0.1", port)

    # Send NEGOTIATE first
    socket.write(send_negotiate_request(socket, message_id: 1))
    socket.flush
    SambaDave::Protocol::Transport.read_message(socket)  # consume response

    # Then send SESSION_SETUP (not yet implemented)
    setup_hdr = SambaDave::Protocol::Header.new(
      command: SambaDave::Protocol::Constants::Commands::SESSION_SETUP,
      message_id: 2
    )
    socket.write(SambaDave::Protocol::Transport.frame(setup_hdr.to_binary_s))
    socket.flush

    raw = SambaDave::Protocol::Transport.read_message(socket)
    socket.close

    hdr = SambaDave::Protocol::Header.read(raw[0, 64])
    expect(hdr.status).to eq(SambaDave::Protocol::Constants::Status::NOT_IMPLEMENTED)
  end
end
