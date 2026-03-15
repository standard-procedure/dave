# frozen_string_literal: true

module SambaDave
  module NTLM
    # SPNEGO/GSS-API wrapping and unwrapping for NTLM tokens.
    #
    # SMB2 authentication uses SPNEGO (RFC 4178) as an outer wrapper around
    # NTLM messages. The security buffer in SESSION_SETUP requests/responses
    # contains ASN.1 DER-encoded SPNEGO tokens.
    #
    # Token types:
    #   - NegTokenInit (0x60 APPLICATION tag) — sent by the client in Round 1
    #     (may contain NTLM Type1 in mechToken field)
    #   - NegTokenResp ([1] context tag = 0xa1) — sent by client in Round 2
    #     (contains NTLM Type3 in responseToken field) and by server in both
    #     rounds (wrapping Type2, or final accept-completed)
    #
    # This module implements a minimal ASN.1 DER encoder/decoder covering only
    # the SPNEGO subset required for SMB2 NTLM authentication. It does NOT
    # implement a general-purpose ASN.1 library.
    #
    module SPNEGO
      # OID bytes for NTLMSSP: 1.3.6.1.4.1.311.2.2.10
      NTLMSSP_OID_BYTES = "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a".b.freeze

      # OID bytes for SPNEGO: 1.3.6.1.5.5.2
      SPNEGO_OID_BYTES = "\x2b\x06\x01\x05\x05\x02".b.freeze

      # NTLM magic bytes that identify a raw NTLM token
      NTLMSSP_MAGIC = "NTLMSSP\x00".b.freeze

      # SPNEGO negState values
      NEGSTATE_ACCEPT_COMPLETED  = 0
      NEGSTATE_ACCEPT_INCOMPLETE = 1

      # ── Public interface ───────────────────────────────────────────────────

      # Unwrap a SPNEGO token to extract the raw NTLM bytes.
      #
      # Handles:
      #   - Raw NTLM (no wrapping) — returned as-is
      #   - NegTokenInit (APPLICATION [0]) — extracts mechToken if present
      #   - NegTokenResp ([1] context) — extracts responseToken
      #
      # @param token [String, nil] the security buffer bytes
      # @return [String, nil] raw NTLM bytes, or nil if not extractable
      def self.unwrap(token)
        return nil if token.nil? || token.empty?

        token = token.b
        return token if token.start_with?(NTLMSSP_MAGIC)

        tag = token[0].ord
        case tag
        when 0x60  # APPLICATION [0] — NegTokenInit (client Round 1)
          parse_neg_token_init(token)
        when 0xa1  # [1] context — NegTokenResp (client Round 2 or server)
          parse_neg_token_resp(token)
        else
          nil
        end
      rescue
        nil
      end

      # Build a NegTokenResp wrapping a Type2 challenge (server Round 1 response).
      #
      # Structure:
      #   [1] NegTokenResp {
      #     [0] negState = accept-incomplete
      #     [1] supportedMech = NTLMSSP OID
      #     [2] responseToken = { NTLM Type2 bytes }
      #   }
      #
      # @param ntlm_type2_bytes [String] serialised NTLM Type2 message
      # @return [String] DER-encoded NegTokenResp
      def self.wrap_challenge(ntlm_type2_bytes)
        ntlm_type2_bytes = ntlm_type2_bytes.b

        # [0] negState = accept-incomplete (1)
        neg_state = der_context(0, der_enumerated(NEGSTATE_ACCEPT_INCOMPLETE))

        # [1] supportedMech = NTLMSSP OID
        supported_mech = der_context(1, der_oid(NTLMSSP_OID_BYTES))

        # [2] responseToken = OCTET STRING { Type2 bytes }
        response_token = der_context(2, der_octet_string(ntlm_type2_bytes))

        # SEQUENCE containing the above
        sequence = der_sequence(neg_state + supported_mech + response_token)

        # [1] NegTokenResp
        der_context(1, sequence)
      end

      # Build a NegTokenResp signalling accept-completed (server Round 2 response).
      #
      # Structure:
      #   [1] NegTokenResp {
      #     [0] negState = accept-completed
      #   }
      #
      # @return [String] DER-encoded NegTokenResp
      def self.wrap_accept_completed
        neg_state = der_context(0, der_enumerated(NEGSTATE_ACCEPT_COMPLETED))
        sequence  = der_sequence(neg_state)
        der_context(1, sequence)
      end

      # ── ASN.1 DER parsers ──────────────────────────────────────────────────

      # Parse an APPLICATION [0] tag (NegTokenInit) and extract the NTLM payload
      # from the mechToken field, if present.
      #
      # @param token [String] binary token starting with 0x60
      # @return [String, nil] raw NTLM bytes or nil
      def self.parse_neg_token_init(token)
        pos = 1  # skip APPLICATION tag byte
        _, pos = der_read_length(token, pos)  # skip APPLICATION length

        # Expect SPNEGO OID
        if token[pos].ord == 0x06
          pos += 1
          oid_len = token[pos].ord
          pos += 1 + oid_len
        end

        # Expect [0] NegTokenInit context tag
        return nil unless pos < token.bytesize && token[pos].ord == 0xa0

        pos += 1
        _, pos = der_read_length(token, pos)

        # Parse NegTokenInit SEQUENCE
        parse_neg_token_init_sequence(token, pos)
      end

      # Parse the inner SEQUENCE of a NegTokenInit and look for [2] mechToken.
      #
      # @param token [String] binary token
      # @param pos [Integer] position of the SEQUENCE tag
      # @return [String, nil]
      def self.parse_neg_token_init_sequence(token, pos)
        return nil unless token[pos].ord == 0x30  # SEQUENCE

        pos += 1
        seq_len, pos = der_read_length(token, pos)
        end_pos = pos + seq_len

        while pos < end_pos
          field_tag = token[pos].ord
          pos += 1
          field_len, pos = der_read_length(token, pos)
          field_start = pos

          if field_tag == 0xa2  # [2] mechToken
            # Contains OCTET STRING { NTLM bytes }
            if token[pos].ord == 0x04
              pos += 1
              oct_len, pos = der_read_length(token, pos)
              return token[pos, oct_len]
            end
          end

          pos = field_start + field_len
        end

        nil
      end

      # Parse a NegTokenResp and extract the responseToken ([2]).
      #
      # @param token [String] binary token starting with 0xa1
      # @return [String, nil] raw NTLM bytes or nil
      def self.parse_neg_token_resp(token)
        pos = 1  # skip [1] tag byte
        _, pos = der_read_length(token, pos)

        # Expect SEQUENCE
        return nil unless token[pos].ord == 0x30

        pos += 1
        seq_len, pos = der_read_length(token, pos)
        end_pos = pos + seq_len

        while pos < end_pos
          field_tag = token[pos].ord
          pos += 1
          field_len, pos = der_read_length(token, pos)
          field_start = pos

          if field_tag == 0xa2  # [2] responseToken
            # Contains OCTET STRING { NTLM bytes }
            if token[pos].ord == 0x04
              pos += 1
              oct_len, pos = der_read_length(token, pos)
              return token[pos, oct_len]
            end
          end

          pos = field_start + field_len
        end

        nil
      end

      # ── ASN.1 DER encoders ─────────────────────────────────────────────────

      # Read a DER length field, returning [length, next_pos].
      # @param data [String] binary data
      # @param pos [Integer] position of the length byte
      # @return [Array<Integer>] [length, pos_after_length]
      def self.der_read_length(data, pos)
        first = data[pos].ord
        if first < 0x80
          [first, pos + 1]
        elsif first == 0x81
          [data[pos + 1].ord, pos + 2]
        elsif first == 0x82
          [((data[pos + 1].ord << 8) | data[pos + 2].ord), pos + 3]
        else
          # Long form (> 2 length bytes) — unlikely in our context
          num_bytes = first & 0x7f
          len = 0
          num_bytes.times { |i| len = (len << 8) | data[pos + 1 + i].ord }
          [len, pos + 1 + num_bytes]
        end
      end

      # Encode a DER length field (short or long form).
      # @param len [Integer]
      # @return [String]
      def self.der_length(len)
        if len < 128
          [len].pack("C")
        elsif len < 256
          "\x81".b + [len].pack("C")
        else
          "\x82".b + [len].pack("n")
        end
      end

      # Build a DER OID TLV (tag 0x06).
      def self.der_oid(oid_bytes)
        ("\x06".b + der_length(oid_bytes.bytesize) + oid_bytes).b
      end

      # Build a DER SEQUENCE TLV (tag 0x30).
      def self.der_sequence(content)
        ("\x30".b + der_length(content.bytesize) + content).b
      end

      # Build a DER OCTET STRING TLV (tag 0x04).
      def self.der_octet_string(bytes)
        ("\x04".b + der_length(bytes.bytesize) + bytes).b
      end

      # Build a DER ENUMERATED TLV (tag 0x0a) for a small integer value.
      def self.der_enumerated(value)
        ("\x0a\x01".b + [value].pack("C")).b
      end

      # Build a DER CONTEXT-SPECIFIC CONSTRUCTED tag [n] (tag = 0xa0 | n).
      def self.der_context(n, content)
        ([0xa0 | n].pack("C") + der_length(content.bytesize) + content).b
      end

      # Build a DER APPLICATION CONSTRUCTED tag [n] (tag = 0x60 | n).
      def self.der_application(n, content)
        ([0x60 | n].pack("C") + der_length(content.bytesize) + content).b
      end
    end
  end
end
