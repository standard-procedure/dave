# frozen_string_literal: true

require "bindata"
require "samba_dave/protocol/constants"
require "samba_dave/tree_connect"

module SambaDave
  module Protocol
    module Commands
      # SMB2 TREE_CONNECT Request body (MS-SMB2 section 2.2.9)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize   — always 9
      #  2       2    Flags           — reserved/flags
      #  4       2    PathOffset      — byte offset of UNC path from start of SMB2 message
      #  6       2    PathLength      — byte count of UNC path (UTF-16LE)
      #  8      var   Buffer          — the UNC path
      #
      class TreeConnectRequest < BinData::Record
        endian :little

        uint16 :structure_size
        uint16 :flags,       initial_value: 0
        uint16 :path_offset  # offset from start of full SMB2 message (including 64-byte header)
        uint16 :path_length  # bytes (not characters)
      end

      # SMB2 TREE_CONNECT Response body (MS-SMB2 section 2.2.10)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize   — always 16
      #  2       1    ShareType       — 0x01=DISK, 0x02=PIPE, 0x03=PRINT
      #  3       1    Reserved        — 0
      #  4       4    ShareFlags      — 0 for basic usage
      #  8       4    Capabilities    — 0 for basic usage
      # 12       4    MaximalAccess   — access rights granted (FILE_ALL_ACCESS = 0x001F01FF)
      #
      class TreeConnectResponse < BinData::Record
        endian :little

        uint16 :structure_size, value: 16
        uint8  :share_type,     initial_value: 0x01  # DISK
        uint8  :reserved,       initial_value: 0
        uint32 :share_flags,    initial_value: 0
        uint32 :capabilities,   initial_value: 0
        uint32 :maximal_access, initial_value: 0x001F01FF  # FILE_ALL_ACCESS
      end

      # SMB2 TREE_DISCONNECT Request body (MS-SMB2 section 2.2.11)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize  — always 4
      #  2       2    Reserved       — must be 0
      #
      class TreeDisconnectRequest < BinData::Record
        endian :little

        uint16 :structure_size
        uint16 :reserved, initial_value: 0
      end

      # SMB2 TREE_DISCONNECT Response body (MS-SMB2 section 2.2.12)
      #
      # Offset  Size  Field
      # ──────  ────  ─────
      #  0       2    StructureSize  — always 4
      #  2       2    Reserved       — must be 0
      #
      class TreeDisconnectResponse < BinData::Record
        endian :little

        uint16 :structure_size, value: 4
        uint16 :reserved, initial_value: 0
      end

      # Handles the SMB2 TREE_CONNECT command.
      #
      # Parses the UNC path (\\server\share), validates the share name, and
      # creates a new TreeConnect in the session if valid.
      #
      # Returns:
      #   status: STATUS_SUCCESS + response_tree_id  — on success
      #   status: STATUS_BAD_NETWORK_NAME            — share not found
      #
      module TreeConnectCmd
        SMB_HEADER_SIZE = 64  # bytes

        # @param body [String] raw request body (after 64-byte SMB2 header)
        # @param session [Session] the authenticated session
        # @param server [Server] for share_name and filesystem
        # @return [Hash] { status:, body:, response_tree_id: }
        def self.handle(body, session:, server:)
          request = TreeConnectRequest.read(body)

          # PathOffset is relative to start of SMB2 message (including header).
          # body starts immediately after the header, so subtract SMB_HEADER_SIZE.
          buf_start   = request.path_offset - SMB_HEADER_SIZE
          path_bytes  = body.b[buf_start, request.path_length] || ""

          # Decode UNC path from UTF-16LE
          unc_path = path_bytes.force_encoding("UTF-16LE").encode("UTF-8", invalid: :replace, undef: :replace)

          # Extract share name: \\server\share → "share" (last component)
          share_name = unc_path.split("\\").last.to_s

          unless share_name.downcase == server.share_name.downcase
            return { status: Constants::Status::BAD_NETWORK_NAME, body: "" }
          end

          # Allocate a new tree_id and create the TreeConnect
          tree_id    = session.allocate_tree_id
          tc         = SambaDave::TreeConnect.new(
            tree_id:    tree_id,
            share_name: share_name,
            filesystem: server.filesystem
          )
          session.add_tree_connect(tc)

          response = TreeConnectResponse.new
          {
            status:           Constants::Status::SUCCESS,
            body:             response.to_binary_s,
            response_tree_id: tree_id
          }
        end
      end

      # Handles the SMB2 TREE_DISCONNECT command.
      #
      # Removes the tree connect identified by tree_id from the session.
      # Always returns STATUS_SUCCESS, even if the tree_id is unknown.
      #
      module TreeDisconnectCmd
        # @param body [String] raw request body (ignored)
        # @param session [Session] the authenticated session
        # @param tree_id [Integer] from the SMB2 request header
        # @return [Hash] { status:, body: }
        def self.handle(body, session:, tree_id:)
          session.remove_tree_connect(tree_id)

          response = TreeDisconnectResponse.new
          { status: Constants::Status::SUCCESS, body: response.to_binary_s }
        end
      end
    end
  end
end
