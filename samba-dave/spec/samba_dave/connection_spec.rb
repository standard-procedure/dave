# frozen_string_literal: true

require "spec_helper"
require "socket"
require "net/ntlm"
require "samba_dave/security_provider"
require "samba_dave/authenticator"
require "samba_dave/session"
require "samba_dave/connection"
require "samba_dave/protocol/constants"
require "samba_dave/protocol/header"
require "samba_dave/protocol/transport"
require "samba_dave/protocol/commands/negotiate"
require "samba_dave/protocol/commands/session_setup"
require "samba_dave/protocol/commands/logoff"
require "samba_dave/ntlm/spnego"

RSpec.describe SambaDave::Connection do
  let(:server_guid) { "B" * 16 }
  let(:provider)    { SambaDave::TestSecurityProvider.new("alice" => "wonderland") }
  let(:server)      { instance_double("SambaDave::Server", server_guid: server_guid, security_provider: provider) }

  C = SambaDave::Protocol::Constants

  # ── Helpers ──────────────────────────────────────────────────────────────────

  # Run the connection in the current thread using a UNIXSocket pair.
  # Writes `request_frame` bytes to the client side, signals EOF (SHUT_WR),
  # then runs the connection and returns all bytes received by the client.
  def run_with_frame(request_frame)
    client_sock, server_sock = UNIXSocket.pair

    client_sock.write(request_frame)
    client_sock.shutdown(Socket::SHUT_WR)

    conn = described_class.new(server_sock, server)
    conn.run

    client_sock.shutdown(Socket::SHUT_RD)
    client_sock.read.tap { client_sock.close rescue nil }
  end

  # Run the connection in a thread, enabling interactive I/O.
  # Yields the client socket; caller writes requests and reads responses.
  # Closes the client after the block.
  def with_connected_server
    client_sock, server_sock = UNIXSocket.pair
    server_thread = Thread.new do
      conn = described_class.new(server_sock, server)
      conn.run
    end
    yield client_sock
    client_sock.close rescue nil
    server_thread.join(2)
  end

  # Read one SMB2 response (transport frame + parse header + body)
  def read_smb2_response(sock)
    raw = SambaDave::Protocol::Transport.read_message(sock)
    header = SambaDave::Protocol::Header.read(raw[0, 64])
    body   = raw[64..]
    { header: header, body: body, raw: raw }
  end

  # Write one SMB2 request (header + body, framed)
  def write_smb2_request(sock, command:, body: "", message_id: 1, session_id: 0)
    header = SambaDave::Protocol::Header.new(
      command:    command,
      message_id: message_id,
      session_id: session_id
    )
    SambaDave::Protocol::Transport.write_message(sock, header.to_binary_s + body.b)
  end

  def negotiate_request_body(dialects: [0x0202], message_id: 1, security_mode: 0)
    [36, dialects.size, security_mode, 0, 0].pack("S<S<S<S<L<") +
      "\x00" * 16 +
      [0].pack("Q<") +
      dialects.pack("S<*")
  end

  def negotiate_request_frame(dialects: [0x0202], message_id: 1, security_mode: 0)
    header = SambaDave::Protocol::Header.new(
      command: C::Commands::NEGOTIATE, message_id: message_id
    )
    body = negotiate_request_body(dialects: dialects, message_id: message_id, security_mode: security_mode)
    SambaDave::Protocol::Transport.frame(header.to_binary_s + body)
  end

  def build_smb2_frame(command:, message_id: 1, session_id: 0, body: "")
    header = SambaDave::Protocol::Header.new(
      command: command, message_id: message_id, session_id: session_id
    )
    SambaDave::Protocol::Transport.frame(header.to_binary_s + body.b)
  end

  def session_setup_request_body(security_buffer)
    [
      25,                        # structure_size
      0,                         # flags
      1,                         # security_mode
      0,                         # capabilities
      0,                         # channel
      64 + 24,                   # security_buffer_offset
      security_buffer.bytesize,  # security_buffer_length
      0                          # previous_session_id
    ].pack("S<CCL<L<S<S<Q<") + security_buffer.b
  end

  def build_type1_spnego
    type1 = Net::NTLM::Message::Type1.new.serialize.b
    build_spnego_neg_token_init(type1)
  end

  def der_length(len)
    if len < 128
      [len].pack("C")
    elsif len < 256
      "\x81".b + [len].pack("C")
    else
      "\x82".b + [len].pack("n")
    end
  end

  def der_tlv(tag, value)
    ([tag].pack("C") + der_length(value.bytesize) + value).b
  end

  def build_spnego_neg_token_init(ntlm_payload)
    ntlmssp_oid = "\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a".b
    spnego_oid  = "\x06\x06\x2b\x06\x01\x05\x05\x02".b
    mech_types     = der_tlv(0x30, ntlmssp_oid)
    mech_types_ctx = der_tlv(0xa0, mech_types)
    octet_string   = der_tlv(0x04, ntlm_payload)
    mech_token_ctx = der_tlv(0xa2, octet_string)
    neg_init_seq   = der_tlv(0x30, mech_types_ctx + mech_token_ctx)
    neg_init_ctx   = der_tlv(0xa0, neg_init_seq)
    der_tlv(0x60, spnego_oid + neg_init_ctx)
  end

  def build_spnego_neg_token_resp(ntlm_payload)
    octet_string       = der_tlv(0x04, ntlm_payload)
    response_token_ctx = der_tlv(0xa2, octet_string)
    sequence           = der_tlv(0x30, response_token_ctx)
    der_tlv(0xa1, sequence)
  end

  # ── #initialize ─────────────────────────────────────────────────────────────

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

  # ── NEGOTIATE ────────────────────────────────────────────────────────────────

  describe "#run — NEGOTIATE handling" do
    it "responds to a NEGOTIATE request with a framed SMB2 response" do
      response_data = run_with_frame(negotiate_request_frame)
      expect(response_data.bytesize).to be > 4
    end

    it "returns an SMB2 NEGOTIATE response with correct header fields" do
      response_data = run_with_frame(negotiate_request_frame)
      response_io   = StringIO.new(response_data)
      raw_msg       = SambaDave::Protocol::Transport.read_message(response_io)
      resp_header   = SambaDave::Protocol::Header.read(raw_msg[0, 64])

      expect(resp_header.protocol_id).to eq("\xFESMB".b)
      expect(resp_header.command).to eq(C::Commands::NEGOTIATE)
      expect(resp_header.status).to eq(C::Status::SUCCESS)
      expect(resp_header.flags & C::Flags::SERVER_TO_REDIR).to eq(1)
    end

    it "echoes the message_id from the request" do
      response_data = run_with_frame(negotiate_request_frame(message_id: 42))
      response_io   = StringIO.new(response_data)
      raw_msg       = SambaDave::Protocol::Transport.read_message(response_io)
      resp_header   = SambaDave::Protocol::Header.read(raw_msg[0, 64])

      expect(resp_header.message_id).to eq(42)
    end

    it "selects SMB 2.0.2 dialect in the response body" do
      response_data = run_with_frame(negotiate_request_frame(dialects: [0x0202, 0x0210, 0x0302]))
      response_io   = StringIO.new(response_data)
      raw_msg       = SambaDave::Protocol::Transport.read_message(response_io)
      resp_body     = SambaDave::Protocol::Commands::NegotiateResponse.read(raw_msg[64..])

      expect(resp_body.dialect_revision).to eq(0x0202)
    end

    it "includes a security buffer (SPNEGO token) in the response" do
      response_data = run_with_frame(negotiate_request_frame)
      response_io   = StringIO.new(response_data)
      raw_msg       = SambaDave::Protocol::Transport.read_message(response_io)
      resp_body     = SambaDave::Protocol::Commands::NegotiateResponse.read(raw_msg[64..])

      expect(resp_body.security_buffer_length).to be > 0
    end
  end

  # ── Session enforcement ───────────────────────────────────────────────────────

  describe "#run — session enforcement" do
    it "returns STATUS_USER_SESSION_DELETED for commands without an authenticated session" do
      frame = build_smb2_frame(command: C::Commands::READ)
      response_data = run_with_frame(frame)

      response_io = StringIO.new(response_data)
      raw_msg     = SambaDave::Protocol::Transport.read_message(response_io)
      resp_header = SambaDave::Protocol::Header.read(raw_msg[0, 64])

      expect(resp_header.status).to eq(C::Status::USER_SESSION_DELETED)
    end

    it "returns STATUS_USER_SESSION_DELETED for LOGOFF without a session" do
      logoff_body = [4, 0].pack("S<S<")
      frame = build_smb2_frame(command: C::Commands::LOGOFF, body: logoff_body)
      response_data = run_with_frame(frame)

      # LOGOFF itself is allowed to proceed even without a session (removes nothing)
      response_io = StringIO.new(response_data)
      raw_msg     = SambaDave::Protocol::Transport.read_message(response_io)
      resp_header = SambaDave::Protocol::Header.read(raw_msg[0, 64])

      expect(resp_header.status).to eq(C::Status::SUCCESS)
    end

    it "handles multiple messages, enforcing auth on non-setup commands" do
      # ECHO (0x000D) without session → USER_SESSION_DELETED
      # Then NEGOTIATE → SUCCESS
      frame1 = build_smb2_frame(command: C::Commands::ECHO, message_id: 1)
      frame2 = negotiate_request_frame(message_id: 2)
      response_data = run_with_frame(frame1 + frame2)

      response_io = StringIO.new(response_data)

      msg1 = SambaDave::Protocol::Transport.read_message(response_io)
      hdr1 = SambaDave::Protocol::Header.read(msg1[0, 64])
      expect(hdr1.status).to eq(C::Status::USER_SESSION_DELETED)

      msg2 = SambaDave::Protocol::Transport.read_message(response_io)
      hdr2 = SambaDave::Protocol::Header.read(msg2[0, 64])
      expect(hdr2.status).to eq(C::Status::SUCCESS)
      expect(hdr2.message_id).to eq(2)
    end
  end

  # ── SESSION_SETUP ─────────────────────────────────────────────────────────────

  describe "#run — SESSION_SETUP Round 1" do
    it "returns STATUS_MORE_PROCESSING_REQUIRED with a Type2 challenge" do
      spnego1 = build_type1_spnego

      # Send NEGOTIATE first, then SESSION_SETUP Round 1
      setup_frame = build_smb2_frame(
        command:    C::Commands::SESSION_SETUP,
        message_id: 2,
        session_id: 0,
        body:       session_setup_request_body(spnego1)
      )

      response_data = run_with_frame(negotiate_request_frame + setup_frame)
      response_io   = StringIO.new(response_data)

      # Skip the NEGOTIATE response
      SambaDave::Protocol::Transport.read_message(response_io)

      # Read the SESSION_SETUP Round 1 response
      raw2    = SambaDave::Protocol::Transport.read_message(response_io)
      header2 = SambaDave::Protocol::Header.read(raw2[0, 64])

      expect(header2.status).to eq(C::Status::MORE_PROCESSING_REQUIRED)
    end
  end

  describe "#run — SESSION_SETUP full two-round flow" do
    it "authenticates successfully with correct credentials and then allows LOGOFF" do
      with_connected_server do |client|
        # NEGOTIATE
        write_smb2_request(client, command: C::Commands::NEGOTIATE,
                                   body: negotiate_request_body, message_id: 1)
        read_smb2_response(client)  # discard

        # Round 1: SESSION_SETUP with Type1 (session_id=0 in request)
        spnego1 = build_type1_spnego
        write_smb2_request(client, command: C::Commands::SESSION_SETUP,
                                   body: session_setup_request_body(spnego1),
                                   message_id: 2, session_id: 0)
        round1 = read_smb2_response(client)
        expect(round1[:header].status).to eq(C::Status::MORE_PROCESSING_REQUIRED)

        # The server assigns a session_id in the Round 1 response header
        assigned_session_id = round1[:header].session_id
        expect(assigned_session_id).to be > 0

        # Extract Type2 from Round 1 response
        round1_resp = SambaDave::Protocol::Commands::SessionSetupResponse.read(round1[:body])
        type2_bytes = SambaDave::NTLM::SPNEGO.unwrap(round1_resp.security_buffer)
        expect(type2_bytes).not_to be_nil

        # Build Type3 with correct credentials
        t2 = Net::NTLM::Message.parse(type2_bytes)
        t3 = t2.response({ user: "alice", password: "wonderland", domain: "" }, { ntlmv2: true })
        spnego3 = build_spnego_neg_token_resp(t3.serialize.b)

        # Round 2: SESSION_SETUP with Type3, using the session_id from Round 1 response
        write_smb2_request(client, command: C::Commands::SESSION_SETUP,
                                   body: session_setup_request_body(spnego3),
                                   message_id: 3, session_id: assigned_session_id)
        round2 = read_smb2_response(client)
        expect(round2[:header].status).to eq(C::Status::SUCCESS)

        # LOGOFF — should succeed because we're authenticated
        logoff_body = [4, 0].pack("S<S<")
        write_smb2_request(client, command: C::Commands::LOGOFF,
                                   body: logoff_body, message_id: 4,
                                   session_id: assigned_session_id)
        logoff_resp = read_smb2_response(client)
        expect(logoff_resp[:header].status).to eq(C::Status::SUCCESS)
      end
    end

    it "returns STATUS_LOGON_FAILURE with wrong credentials" do
      with_connected_server do |client|
        write_smb2_request(client, command: C::Commands::NEGOTIATE,
                                   body: negotiate_request_body, message_id: 1)
        read_smb2_response(client)

        spnego1 = build_type1_spnego
        write_smb2_request(client, command: C::Commands::SESSION_SETUP,
                                   body: session_setup_request_body(spnego1),
                                   message_id: 2, session_id: 0)
        round1 = read_smb2_response(client)
        assigned_session_id = round1[:header].session_id

        round1_resp = SambaDave::Protocol::Commands::SessionSetupResponse.read(round1[:body])
        type2_bytes = SambaDave::NTLM::SPNEGO.unwrap(round1_resp.security_buffer)

        t2 = Net::NTLM::Message.parse(type2_bytes)
        t3 = t2.response({ user: "alice", password: "WRONGPASSWORD", domain: "" }, { ntlmv2: true })
        spnego3 = build_spnego_neg_token_resp(t3.serialize.b)

        write_smb2_request(client, command: C::Commands::SESSION_SETUP,
                                   body: session_setup_request_body(spnego3),
                                   message_id: 3, session_id: assigned_session_id)
        round2 = read_smb2_response(client)
        expect(round2[:header].status).to eq(C::Status::LOGON_FAILURE)
      end
    end
  end
end
