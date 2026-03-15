# frozen_string_literal: true

require "bindata"
require "samba_dave/protocol/constants"

module SambaDave
  module Protocol
    module Commands
      # ── BinData structures ───────────────────────────────────────────────────

      # SMB2 NEGOTIATE Request body (MS-SMB2 section 2.2.3)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize     — always 36
      #  2       2    DialectCount      — number of dialects in the list
      #  4       2    SecurityMode      — signing enabled/required flags
      #  6       2    Reserved          — must be 0
      #  8       4    Capabilities      — client capabilities
      # 12      16    ClientGuid        — 16-byte GUID
      # 28       8    ClientStartTime   — FILETIME (or NegotiateContextOffset for 3.1.1)
      # 36    2*n    Dialects          — array of 2-byte dialect codes
      #
      class NegotiateRequest < BinData::Record
        endian :little

        uint16 :structure_size    # always 36
        uint16 :dialect_count
        uint16 :security_mode
        uint16 :reserved
        uint32 :capabilities
        string :client_guid, length: 16
        uint64 :client_start_time   # overloaded in SMB 3.1.1 — ignore for now
        array  :dialects, type: :uint16le, initial_length: :dialect_count
      end

      # SMB2 NEGOTIATE Response body (MS-SMB2 section 2.2.4)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize              — always 65
      #  2       2    SecurityMode               — signing flags
      #  4       2    DialectRevision            — selected dialect
      #  6       2    NegotiateContextCount/Rsv  — reserved for SMB < 3.1.1
      #  8      16    ServerGuid                 — 16-byte GUID
      # 24       4    Capabilities               — server capabilities
      # 28       4    MaxTransactSize
      # 32       4    MaxReadSize
      # 36       4    MaxWriteSize
      # 40       8    SystemTime                 — current time (FILETIME)
      # 48       8    ServerStartTime            — when server started (0 for our impl)
      # 56       2    SecurityBufferOffset       — offset from start of SMB2 message
      # 58       2    SecurityBufferLength       — length of security buffer
      # 60       4    NegotiateContextOffset/Rsv — reserved for SMB < 3.1.1
      # 64     var    SecurityBuffer             — SPNEGO token
      #
      class NegotiateResponse < BinData::Record
        endian :little

        uint16 :structure_size,              value: 65
        uint16 :security_mode,              initial_value: 0
        uint16 :dialect_revision,           initial_value: 0
        uint16 :negotiate_context_count,    initial_value: 0  # reserved for SMB < 3.1.1
        string :server_guid,               length: 16
        uint32 :capabilities,              initial_value: 0
        uint32 :max_transact_size,         initial_value: 8_388_608  # 8 MB
        uint32 :max_read_size,             initial_value: 8_388_608
        uint32 :max_write_size,            initial_value: 8_388_608
        uint64 :system_time,              initial_value: 0
        uint64 :server_start_time,        initial_value: 0
        uint16 :security_buffer_offset,   initial_value: 128  # 64 (header) + 64 (body fixed)
        uint16 :security_buffer_length,   initial_value: 0
        uint32 :negotiate_context_offset, initial_value: 0   # reserved for SMB < 3.1.1
        string :security_buffer, read_length: :security_buffer_length
      end

      # ── Negotiate command handler ────────────────────────────────────────────

      # Handles the SMB2 NEGOTIATE command.
      #
      # Parses the client's dialect list and builds a NEGOTIATE response
      # selecting SMB 2.0.2 (the simplest dialect). Includes a SPNEGO
      # NegTokenInit security buffer advertising NTLMSSP.
      #
      module Negotiate
        # Minimal SPNEGO/GSS-API token builder.
        #
        # The security buffer in a NEGOTIATE response is a GSS-API Initial
        # Context Token (Application [0] tag) wrapping a SPNEGO NegTokenInit
        # that advertises the NTLMSSP mechanism.
        #
        # The token is ASN.1 DER encoded. Since we only need to produce
        # one fixed structure (NegTokenInit with one OID), we hard-code
        # the DER bytes rather than pulling in a full ASN.1 library.
        #
        # Structure:
        #   APPLICATION [0] (0x60)
        #     OID 1.3.6.1.5.5.2 (SPNEGO)
        #     [0] NegTokenInit
        #       SEQUENCE
        #         [0] mechTypes
        #           SEQUENCE OF
        #             OID 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
        #
        module SPNEGO
          # OID 1.3.6.1.4.1.311.2.2.10 — NTLMSSP mechanism
          NTLMSSP_OID_BYTES = "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a".b.freeze

          # OID 1.3.6.1.5.5.2 — SPNEGO
          SPNEGO_OID_BYTES = "\x2b\x06\x01\x05\x05\x02".b.freeze

          # Build a minimal SPNEGO NegTokenInit (GSS-API initial context token)
          # advertising NTLMSSP as the sole supported security mechanism.
          #
          # @return [String] DER-encoded binary token
          def self.neg_token_init
            # OID TLV for NTLMSSP
            ntlmssp_oid_tlv = der_oid(NTLMSSP_OID_BYTES)

            # SEQUENCE OF OID (mechTypes inner)
            mech_types_seq = der_sequence(ntlmssp_oid_tlv)

            # [0] mechTypes EXPLICIT tag
            mech_types_ctx = der_context(0, mech_types_seq)

            # SEQUENCE (NegTokenInit body)
            neg_token_init_seq = der_sequence(mech_types_ctx)

            # [0] NegTokenInit EXPLICIT context tag
            neg_token_init_ctx = der_context(0, neg_token_init_seq)

            # OID TLV for SPNEGO mechanism
            spnego_oid_tlv = der_oid(SPNEGO_OID_BYTES)

            # APPLICATION [0] wrapper (GSS-API outer)
            application_content = spnego_oid_tlv + neg_token_init_ctx
            der_application(0, application_content)
          end

          private

          # DER length encoding (definite, short or long form)
          def self.der_length(len)
            if len < 128
              [len].pack("C")
            elsif len < 256
              "\x81".b + [len].pack("C")
            else
              "\x82".b + [len].pack("n")
            end
          end

          # DER OID TLV: tag=0x06
          def self.der_oid(oid_bytes)
            ("\x06".b + der_length(oid_bytes.bytesize) + oid_bytes).b
          end

          # DER SEQUENCE TLV: tag=0x30
          def self.der_sequence(content)
            ("\x30".b + der_length(content.bytesize) + content).b
          end

          # DER CONTEXT-SPECIFIC EXPLICIT tag [n] (constructed): tag = 0xa0 | n
          def self.der_context(n, content)
            ([0xa0 | n].pack("C") + der_length(content.bytesize) + content).b
          end

          # DER APPLICATION tag [n] (constructed): tag = 0x60 | n
          def self.der_application(n, content)
            ([0x60 | n].pack("C") + der_length(content.bytesize) + content).b
          end
        end

        # Constant: max buffer sizes (8 MB)
        MAX_BUFFER_SIZE = 8_388_608

        # The current time as a Windows FILETIME (100-ns intervals since 1601-01-01)
        def self.current_filetime
          now = Time.now
          (now.to_i * 10_000_000) + (now.nsec / 100) + Constants::FILETIME_EPOCH_DIFF
        end

        # Handle a parsed NegotiateRequest.
        #
        # @param request [NegotiateRequest] parsed NEGOTIATE request body
        # @param server_guid [String] 16-byte server GUID
        # @return [String] serialised NegotiateResponse body (binary)
        def self.handle(request, server_guid:)
          # Select the dialect: prefer SMB 2.0.2; accept any known dialect
          dialects = request.dialects.to_a
          selected = if dialects.include?(Constants::Dialects::SMB2_0_2)
            Constants::Dialects::SMB2_0_2
          else
            # Fall back to SMB 2.0.2 if offered dialect we don't understand
            Constants::Dialects::SMB2_0_2
          end

          spnego_token = SPNEGO.neg_token_init

          response = NegotiateResponse.new(
            security_mode:          Constants::SecurityMode::SIGNING_ENABLED,
            dialect_revision:       selected,
            server_guid:            server_guid,
            capabilities:           0,
            max_transact_size:      MAX_BUFFER_SIZE,
            max_read_size:          MAX_BUFFER_SIZE,
            max_write_size:         MAX_BUFFER_SIZE,
            system_time:            current_filetime,
            server_start_time:      0,
            security_buffer_offset: 128,  # 64-byte SMB2 header + 64-byte fixed body
            security_buffer_length: spnego_token.bytesize,
            security_buffer:        spnego_token
          )

          response.to_binary_s
        end
      end
    end
  end
end
