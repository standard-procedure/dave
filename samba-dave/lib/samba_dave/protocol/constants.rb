# frozen_string_literal: true

module SambaDave
  module Protocol
    # SMB2 protocol constants: command codes, status codes, flags, dialects.
    module Constants
      # Protocol identification signatures (binary, 4 bytes each)
      PROTOCOL_ID_SMB2 = "\xFESMB".b.freeze
      PROTOCOL_ID_SMB1 = "\xFFSMB".b.freeze

      # SMB2 Command codes (2 bytes, little-endian in header)
      module Commands
        NEGOTIATE        = 0x0000
        SESSION_SETUP    = 0x0001
        LOGOFF           = 0x0002
        TREE_CONNECT     = 0x0003
        TREE_DISCONNECT  = 0x0004
        CREATE           = 0x0005
        CLOSE            = 0x0006
        FLUSH            = 0x0007
        READ             = 0x0008
        WRITE            = 0x0009
        LOCK             = 0x000A
        IOCTL            = 0x000B
        CANCEL           = 0x000C
        ECHO             = 0x000D
        QUERY_DIRECTORY  = 0x000E
        CHANGE_NOTIFY    = 0x000F
        QUERY_INFO       = 0x0010
        SET_INFO         = 0x0011
        OPLOCK_BREAK     = 0x0012
      end

      # NT Status codes returned in SMB2 responses
      module Status
        SUCCESS                   = 0x00000000
        MORE_PROCESSING_REQUIRED  = 0xC0000016
        NOT_IMPLEMENTED           = 0xC0000002
        INVALID_PARAMETER         = 0xC000000D
        NO_SUCH_FILE              = 0xC000000F
        ACCESS_DENIED             = 0xC0000022
        OBJECT_NAME_NOT_FOUND     = 0xC0000034
        OBJECT_NAME_COLLISION     = 0xC0000035
        OBJECT_PATH_NOT_FOUND     = 0xC000003A
        SHARING_VIOLATION         = 0xC0000043
        LOGON_FAILURE             = 0xC000006D
        FILE_IS_A_DIRECTORY       = 0xC00000BA
        BAD_NETWORK_NAME          = 0xC00000CC
        NOT_A_DIRECTORY           = 0xC00000FB
        INVALID_HANDLE            = 0xC0000008
        INVALID_INFO_CLASS        = 0xC0000003
        INVALID_DEVICE_REQUEST    = 0xC0000010
        BUFFER_OVERFLOW           = 0x80000005
        NO_MORE_FILES             = 0x80000006
        NOT_SUPPORTED             = 0xC00000BB
        USER_SESSION_DELETED      = 0xC0000203
      end

      # Header flags (32-bit bitmask at offset 16)
      module Flags
        SERVER_TO_REDIR    = 0x00000001  # Response bit — set by server on all responses
        ASYNC_COMMAND      = 0x00000002  # Async header format
        RELATED_OPERATIONS = 0x00000004  # Compound related
        SIGNED             = 0x00000008  # Message is signed
        DFS_OPERATIONS     = 0x10000000  # DFS operation
      end

      # SMB2 dialect revision codes
      module Dialects
        SMB2_0_2 = 0x0202  # SMB 2.0.2 — simplest, target for Phase 1
        SMB2_1   = 0x0210  # SMB 2.1 — credits, leasing
        SMB3_0   = 0x0300  # SMB 3.0
        SMB3_0_2 = 0x0302  # SMB 3.0.2
        SMB3_1_1 = 0x0311  # SMB 3.1.1 — pre-auth integrity
        WILDCARD = 0x02FF  # Wildcard used in multi-protocol negotiate response
      end

      # Security mode flags (2 bytes)
      module SecurityMode
        SIGNING_ENABLED  = 0x0001
        SIGNING_REQUIRED = 0x0002
      end

      # File attribute flags
      module FileAttributes
        READONLY  = 0x00000001
        HIDDEN    = 0x00000002
        SYSTEM    = 0x00000004
        DIRECTORY = 0x00000010
        ARCHIVE   = 0x00000020
        NORMAL    = 0x00000080
      end

      # FILETIME epoch offset: 100-nanosecond intervals from 1601-01-01 to 1970-01-01
      FILETIME_EPOCH_DIFF = 116_444_736_000_000_000
    end
  end
end
