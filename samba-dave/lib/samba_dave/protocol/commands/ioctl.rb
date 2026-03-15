# frozen_string_literal: true

require "bindata"
require "samba_dave/protocol/constants"

module SambaDave
  module Protocol
    module Commands
      # SMB2 IOCTL Request body — fixed 56-byte portion (MS-SMB2 section 2.2.31)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize          — always 57
      #  2       2    Reserved
      #  4       4    CtlCode
      #  8       8    FileId.Persistent
      # 16       8    FileId.Volatile
      # 24       4    InputOffset
      # 28       4    InputCount
      # 32       4    MaxInputResponse
      # 36       4    OutputOffset
      # 40       4    OutputCount
      # 44       4    MaxOutputResponse
      # 48       4    Flags                  — 0x00000001 = IS_FSCTL
      # 52       4    Reserved2
      #
      class IoctlRequest < BinData::Record
        endian :little

        uint16 :structure_size
        uint16 :reserved,            initial_value: 0
        uint32 :ctl_code
        uint64 :file_id_persistent
        uint64 :file_id_volatile
        uint32 :input_offset
        uint32 :input_count
        uint32 :max_input_response
        uint32 :output_offset
        uint32 :output_count
        uint32 :max_output_response
        uint32 :flags
        uint32 :reserved2,           initial_value: 0
      end

      # SMB2 IOCTL Response body — fixed 48-byte portion (MS-SMB2 section 2.2.32)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize          — always 49 (includes 1 variable byte)
      #  2       2    Reserved
      #  4       4    CtlCode
      #  8       8    FileId.Persistent
      # 16       8    FileId.Volatile
      # 24       4    InputOffset
      # 28       4    InputCount
      # 32       4    OutputOffset           — offset from SMB2 header = 64+48 = 112
      # 36       4    OutputCount
      # 40       4    Flags
      # 44       4    Reserved2
      # 48      var   Buffer
      #
      class IoctlResponse < BinData::Record
        endian :little

        uint16 :structure_size,   value: 49
        uint16 :reserved,         initial_value: 0
        uint32 :ctl_code,         initial_value: 0
        uint64 :file_id_persistent, initial_value: 0
        uint64 :file_id_volatile,   initial_value: 0
        uint32 :input_offset,     initial_value: 0
        uint32 :input_count,      initial_value: 0
        uint32 :output_offset,    initial_value: 112  # 64-byte header + 48-byte fixed
        uint32 :output_count,     initial_value: 0
        uint32 :flags,            initial_value: 0
        uint32 :reserved2,        initial_value: 0
        string :output_buffer,    read_length: :output_count
      end

      # Handles the SMB2 IOCTL command (MS-SMB2 section 3.3.5.15).
      #
      # Supports:
      #   FSCTL_VALIDATE_NEGOTIATE_INFO (0x00140204) — SMB 3.x client compatibility
      #   FSCTL_GET_REPARSE_POINT       (0x000900A8) → STATUS_NOT_A_REPARSE_POINT
      #   All others                                 → STATUS_NOT_SUPPORTED
      #
      module Ioctl
        # FSCTL codes
        FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204
        FSCTL_GET_REPARSE_POINT       = 0x000900A8

        # Fixed size of IoctlRequest (BinData record)
        IOCTL_REQUEST_FIXED_SIZE = 56
        SMB_HEADER_SIZE          = 64

        # @param body [String] raw request body (after 64-byte SMB2 header)
        # @param server_guid [String] 16-byte server GUID (from Server)
        # @param dialect [Integer] negotiated SMB2 dialect (default 0x0202)
        # @return [Hash] { status: Integer, body: String }
        def self.handle(body, server_guid:, dialect: 0x0202)
          request = IoctlRequest.read(body)

          case request.ctl_code
          when FSCTL_VALIDATE_NEGOTIATE_INFO
            handle_validate_negotiate_info(body, request, server_guid: server_guid, dialect: dialect)
          when FSCTL_GET_REPARSE_POINT
            { status: Constants::Status::NOT_A_REPARSE_POINT, body: "" }
          else
            { status: Constants::Status::NOT_SUPPORTED, body: "" }
          end
        rescue => e
          { status: Constants::Status::INVALID_PARAMETER, body: "" }
        end

        # ── Private helpers ────────────────────────────────────────────────────

        # Handle FSCTL_VALIDATE_NEGOTIATE_INFO.
        #
        # SMB 3.x clients send this immediately after authentication to verify
        # that the negotiate phase was not tampered with. The server must respond
        # with its own capabilities, GUID, security mode, and the negotiated
        # dialect. Without a valid response, SMB 3.x clients disconnect.
        #
        # Response layout (VALIDATE_NEGOTIATE_INFO Response, MS-SMB2 2.2.32.6):
        #   Capabilities (4 bytes) — server capabilities
        #   Guid        (16 bytes) — server GUID
        #   SecurityMode (2 bytes) — server security mode (SIGNING_ENABLED = 0x0001)
        #   Dialect      (2 bytes) — negotiated dialect
        #
        def self.handle_validate_negotiate_info(body, request, server_guid:, dialect:)
          # Build the ValidateNegotiateInfo response buffer
          capabilities  = 0  # SMB 2.0.2: no special capabilities
          security_mode = Constants::SecurityMode::SIGNING_ENABLED

          out_buf = [capabilities].pack("L<")
          out_buf += server_guid.b
          out_buf += [security_mode, dialect].pack("S<S<")

          response = IoctlResponse.new(
            ctl_code:       request.ctl_code,
            output_count:   out_buf.bytesize,
            output_buffer:  out_buf
          )
          { status: Constants::Status::SUCCESS, body: response.to_binary_s }
        end

        private_class_method :handle_validate_negotiate_info
      end
    end
  end
end
