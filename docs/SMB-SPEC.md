# SMB2/3 Protocol — Distilled Reference for samba-dave

> LLM-friendly reference for implementing an SMB2 file server in Ruby.
> Source: [MS-SMB2] (Microsoft Open Specifications), Samba project docs, Wireshark wiki.

---

## Table of Contents

1. [SMB2 vs SMB3 — What Matters](#1-smb2-vs-smb3--what-matters)
2. [Dialect Negotiation](#2-dialect-negotiation)
3. [TCP Framing](#3-tcp-framing)
4. [SMB2 Header Structure](#4-smb2-header-structure)
5. [Session Model](#5-session-model)
6. [Core Commands](#6-core-commands)
7. [File Handle Model](#7-file-handle-model)
8. [Locking Model](#8-locking-model)
9. [Authentication — NTLM Wire Format](#9-authentication--ntlm-wire-format)
10. [Status Codes](#10-status-codes)
11. [What a Minimal Server Must Implement](#11-what-a-minimal-server-must-implement)
12. [Existing Ruby/Python Libraries](#12-existing-rubypython-libraries)

---

## 1. SMB2 vs SMB3 — What Matters

SMB2 and SMB3 share the same wire format. "SMB3" is really a set of dialect versions within the SMB2 protocol family. The key differences:

| Feature | SMB 2.0.2 | SMB 2.1 | SMB 3.0 | SMB 3.0.2 | SMB 3.1.1 |
|---------|-----------|---------|---------|-----------|-----------|
| Basic file ops | ✅ | ✅ | ✅ | ✅ | ✅ |
| Durable handles | ❌ | ✅ | ✅ | ✅ | ✅ |
| Leases (dir oplocks) | ❌ | ❌ | ✅ | ✅ | ✅ |
| Encryption | ❌ | ❌ | ✅ | ✅ | ✅ |
| Secure negotiate | ❌ | ❌ | ❌ | ❌ | ✅ |
| Pre-auth integrity | ❌ | ❌ | ❌ | ❌ | ✅ |
| Compression | ❌ | ❌ | ❌ | ❌ | ✅ |
| Multi-channel | ❌ | ❌ | ✅ | ✅ | ✅ |

### What We Need to Care About

**For Windows 10/11 compatibility:** Windows 10+ defaults to SMB 3.1.1 but will negotiate down to 2.0.2. However, Windows may require signing or encryption for certain dialects. Supporting **SMB 2.0.2 and 2.1** gets us basic compatibility. Supporting **3.0.2** gets us macOS compatibility without issues.

**For macOS compatibility:** macOS Finder supports SMB 2 and 3. Modern macOS (Sonoma+) prefers SMB 3.0.2 or 3.1.1 but will negotiate down to 2.0.2. Some newer macOS versions may require SMB 3.x for certain features.

**Recommendation:** Start with **SMB 2.0.2** dialect only (simplest). Add **2.1** in Phase 2. Add **3.0.2** when encryption/signing is needed. Skip 3.1.1 unless required.

---

## 2. Dialect Negotiation

### Multi-Protocol Negotiate

Clients may send an SMB1-style `COM_NEGOTIATE` packet listing both SMB1 and SMB2 dialect strings. If the server sees `"SMB 2.002"` or `"SMB 2.???"` in the list, it responds with an SMB2 NEGOTIATE Response.

### SMB2 Negotiate

Modern clients send an SMB2 NEGOTIATE Request directly.

**Request contains:**
- `DialectCount` — number of dialects offered
- `Dialects[]` — array of 16-bit dialect codes:
  - `0x0202` = SMB 2.0.2
  - `0x0210` = SMB 2.1
  - `0x0300` = SMB 3.0
  - `0x0302` = SMB 3.0.2
  - `0x0311` = SMB 3.1.1
- `SecurityMode` — signing enabled/required flags
- `Capabilities` — DFS, leasing, multi-credit, etc.
- `ClientGuid` — 16-byte GUID identifying the client
- `NegotiateContextList` (SMB 3.1.1 only) — pre-auth integrity, encryption caps

**Response contains:**
- `DialectRevision` — selected dialect
- `SecurityMode` — server signing flags
- `ServerGuid` — 16-byte GUID
- `Capabilities` — server capabilities
- `MaxTransactSize`, `MaxReadSize`, `MaxWriteSize` — buffer limits
- `SecurityBuffer` — GSS/SPNEGO token for auth init

### Multi-Protocol Negotiate Handling

When a client sends an SMB1 `COM_NEGOTIATE` containing `"SMB 2.???"`:

1. Read the SMB1 negotiate request
2. Check dialect strings for SMB2 indicators
3. If found, respond with an SMB2 NEGOTIATE Response (dialect `0x02FF` = wildcard)
4. Client then sends a proper SMB2 NEGOTIATE Request
5. Server responds with the final negotiated dialect

**For samba-dave:** Initially, only support direct SMB2 negotiation. If a client sends SMB1 `COM_NEGOTIATE`, detect the `\xFFSMB` signature and respond with an SMB2 negotiate response using dialect `0x02FF` to force the client to re-negotiate with SMB2.

---

## 3. TCP Framing

SMB2 runs over TCP port 445 using **Direct TCP Transport** (not NetBIOS).

### Frame Format

Every SMB2 message is prefixed with a 4-byte **NetBIOS Session Service** header:

```
┌──────────────────────────────┐
│ 0x00 (1 byte) — always zero │
│ Length (3 bytes) — big-endian│
├──────────────────────────────┤
│ SMB2 Message (variable)     │
│ (header + command payload)  │
└──────────────────────────────┘
```

- The first byte is always `0x00` (session message type)
- The next 3 bytes are the message length in big-endian byte order
- Maximum message size: 16,776,960 bytes (2^24 - 1 - overhead)

### Reading a Message

```ruby
# Pseudocode for reading one SMB2 message
def read_message(socket)
  header = socket.read(4)
  type = header[0].ord        # Always 0x00
  length = (header[1].ord << 16) | (header[2].ord << 8) | header[3].ord
  data = socket.read(length)  # The full SMB2 message
  data
end
```

### Writing a Message

```ruby
def write_message(socket, data)
  length = data.bytesize
  header = [0x00, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF].pack("C4")
  socket.write(header + data)
end
```

---

## 4. SMB2 Header Structure

Every SMB2 message starts with a fixed 64-byte header. All multi-byte fields are **little-endian**.

### Sync Header (non-async)

```
Offset  Size  Field
──────  ────  ─────
 0       4    ProtocolId        — 0xFE, 'S', 'M', 'B' (0x424D53FE LE)
 4       2    StructureSize     — Always 64
 6       2    CreditCharge      — Credits consumed (0 for 2.0.2)
 8       4    Status            — NT status code (requests: 0; responses: result)
12       2    Command           — Command code (see below)
14       2    CreditReq/Resp    — Credits requested/granted
16       4    Flags             — Bit flags (see below)
20       4    NextCommand       — Offset to next command in compound (0 if none)
24       8    MessageId         — Unique message identifier
32       4    Reserved          — (or ProcessId for SMB1 compat)
36       4    TreeId            — Tree connect identifier
40       8    SessionId         — Session identifier
48      16    Signature         — Message signature (if signed)
```

### Command Codes

| Code | Name | Purpose |
|------|------|---------|
| 0x0000 | NEGOTIATE | Dialect negotiation |
| 0x0001 | SESSION_SETUP | Authentication |
| 0x0002 | LOGOFF | End session |
| 0x0003 | TREE_CONNECT | Connect to share |
| 0x0004 | TREE_DISCONNECT | Disconnect from share |
| 0x0005 | CREATE | Open/create file or directory |
| 0x0006 | CLOSE | Close file handle |
| 0x0007 | FLUSH | Flush file buffers |
| 0x0008 | READ | Read file data |
| 0x0009 | WRITE | Write file data |
| 0x000A | LOCK | Byte-range lock |
| 0x000B | IOCTL | I/O control |
| 0x000C | CANCEL | Cancel pending request |
| 0x000D | ECHO | Keep-alive ping |
| 0x000E | QUERY_DIRECTORY | List directory contents |
| 0x000F | CHANGE_NOTIFY | Watch for changes |
| 0x0010 | QUERY_INFO | Get file/fs metadata |
| 0x0011 | SET_INFO | Set file/fs metadata |
| 0x0012 | OPLOCK_BREAK | Oplock break notification |

### Key Flags

| Value | Name | Meaning |
|-------|------|---------|
| 0x00000001 | SERVER_TO_REDIR | Response (set by server) |
| 0x00000002 | ASYNC_COMMAND | Async header format |
| 0x00000004 | RELATED_OPERATIONS | Compound related |
| 0x00000008 | SIGNED | Message is signed |
| 0x10000000 | DFS_OPERATIONS | DFS operation |

---

## 5. Session Model

### Connection Lifecycle

```
Client                              Server
  │                                    │
  │──── TCP Connect (port 445) ───────▶│
  │                                    │
  │──── NEGOTIATE Request ────────────▶│  ← Dialect list
  │◀─── NEGOTIATE Response ───────────│  ← Selected dialect, server GUID, security blob
  │                                    │
  │──── SESSION_SETUP Request ────────▶│  ← NTLM NEGOTIATE_MESSAGE (Type 1)
  │◀─── SESSION_SETUP Response ───────│  ← NTLM CHALLENGE_MESSAGE (Type 2) + STATUS_MORE_PROCESSING
  │                                    │
  │──── SESSION_SETUP Request ────────▶│  ← NTLM AUTHENTICATE_MESSAGE (Type 3)
  │◀─── SESSION_SETUP Response ───────│  ← STATUS_SUCCESS + SessionId
  │                                    │
  │──── TREE_CONNECT Request ─────────▶│  ← Share path (\\server\share)
  │◀─── TREE_CONNECT Response ────────│  ← TreeId + share type
  │                                    │
  │──── CREATE Request ───────────────▶│  ← Open file
  │◀─── CREATE Response ─────────────│  ← FileId (durable handle)
  │                                    │
  │──── READ / WRITE / QUERY_INFO ────▶│  ← File operations
  │◀─── Responses ────────────────────│
  │                                    │
  │──── CLOSE Request ────────────────▶│  ← Close file
  │◀─── CLOSE Response ──────────────│
  │                                    │
  │──── TREE_DISCONNECT ──────────────▶│
  │◀─── Response ─────────────────────│
  │                                    │
  │──── LOGOFF ────────────────────────▶│
  │◀─── Response ─────────────────────│
```

### State Objects

| Object | Identifier | Scope | Purpose |
|--------|-----------|-------|---------|
| Connection | TCP socket | Per-client | Transport-level state |
| Session | SessionId (8 bytes) | Per-connection | Authenticated user context |
| Tree Connect | TreeId (4 bytes) | Per-session | Mounted share |
| Open (File Handle) | FileId (16 bytes) | Per-tree | Open file/directory |

### Multiple Sessions

One TCP connection can have multiple sessions (different users). Each session can have multiple tree connects (different shares). Each tree connect can have multiple opens (different files).

### Credits

SMB2 uses a credit-based flow control system. The server grants credits to the client; each request consumes credits. For a simple server, grant generous credits (e.g., 512) and don't worry about fine-tuning.

---

## 6. Core Commands

### NEGOTIATE (0x0000)

See [§2 Dialect Negotiation](#2-dialect-negotiation).

### SESSION_SETUP (0x0001)

**Request:** Contains security buffer (SPNEGO/NTLM token).
**Response:** Contains security buffer (challenge/accept), SessionId, SessionFlags.

Two round trips for NTLM:
1. Client sends Type 1 (NEGOTIATE) → Server sends Type 2 (CHALLENGE) with `STATUS_MORE_PROCESSING_REQUIRED`
2. Client sends Type 3 (AUTHENTICATE) → Server validates, sends `STATUS_SUCCESS`

### TREE_CONNECT (0x0003)

**Request:** Path in UNC format (`\\server\share`) as UTF-16LE.
**Response:** ShareType (DISK=0x01, PIPE=0x02, PRINT=0x03), ShareFlags, Capabilities, MaximalAccess.

For samba-dave: always return ShareType=DISK.

### CREATE (0x0005)

The most complex command. Opens or creates a file/directory.

**Key request fields:**
- `DesiredAccess` — read, write, delete, etc. (bit flags)
- `FileAttributes` — normal, directory, hidden, etc.
- `ShareAccess` — how others can access while open
- `CreateDisposition` — SUPERSEDE, OPEN, CREATE, OPEN_IF, OVERWRITE, OVERWRITE_IF
- `CreateOptions` — DIRECTORY_FILE, NON_DIRECTORY_FILE, etc.
- `Name` — file path relative to share root (UTF-16LE)

**Key response fields:**
- `FileId` — 16-byte handle (Persistent + Volatile)
- `CreateAction` — FILE_SUPERSEDED, FILE_OPENED, FILE_CREATED, FILE_OVERWRITTEN
- `CreationTime`, `LastAccessTime`, `LastWriteTime`, `ChangeTime` — FILETIME format
- `AllocationSize`, `EndOfFile` — file size info
- `FileAttributes` — attributes of opened file

**CreateDisposition values:**
| Value | Name | Exists | Doesn't Exist |
|-------|------|--------|---------------|
| 0 | SUPERSEDE | Replace | Create |
| 1 | OPEN | Open | Fail |
| 2 | CREATE | Fail | Create |
| 3 | OPEN_IF | Open | Create |
| 4 | OVERWRITE | Overwrite | Fail |
| 5 | OVERWRITE_IF | Overwrite | Create |

### CLOSE (0x0006)

Closes a FileId. Simple request/response.

### READ (0x0008)

**Request:** FileId, Offset, Length, MinimumCount.
**Response:** Data buffer.

### WRITE (0x0009)

**Request:** FileId, Offset, Data buffer.
**Response:** Bytes written.

### QUERY_INFO (0x0010)

Queries file, filesystem, or security metadata.

**InfoType values:**
| Value | Type | Purpose |
|-------|------|---------|
| 0x01 | FILE | File metadata (size, times, attributes) |
| 0x02 | FILESYSTEM | Volume info (size, label, capabilities) |
| 0x03 | SECURITY | Security descriptor |
| 0x04 | QUOTA | Quota info |

**Common FileInformationClass values (InfoType=FILE):**
| Value | Class | Returns |
|-------|-------|---------|
| 0x04 | FileBasicInformation | Timestamps, attributes |
| 0x05 | FileStandardInformation | AllocationSize, EndOfFile, NumberOfLinks, DeletePending, Directory |
| 0x06 | FileInternalInformation | IndexNumber (inode) |
| 0x07 | FileEaInformation | EA size |
| 0x12 | FileAllInformation | All of the above combined |
| 0x15 | FileNetworkOpenInformation | Timestamps, size, attributes (common query) |
| 0x22 | FileStreamInformation | NTFS streams |

**Common FsInformationClass values (InfoType=FILESYSTEM):**
| Value | Class | Returns |
|-------|-------|---------|
| 0x01 | FileFsVolumeInformation | Volume label, serial number |
| 0x03 | FileFsSizeInformation | Total/available allocation units |
| 0x05 | FileFsAttributeInformation | FS name, max filename length, flags |
| 0x06 | FileFsControlInformation | Quota info |
| 0x07 | FileFsFullSizeInformation | More detailed size info |

### SET_INFO (0x0011)

Sets file/filesystem metadata. Same InfoType/Class system as QUERY_INFO.

### QUERY_DIRECTORY (0x000E)

Lists directory contents.

**Request:** FileId (of open directory), FileInformationClass, Pattern (wildcard), Flags.
**Response:** Buffer containing array of file info structures.

**Common FileInformationClass values:**
| Value | Class | Returns |
|-------|-------|---------|
| 0x01 | FileDirectoryInformation | Basic listing |
| 0x02 | FileFullDirectoryInformation | + EA size |
| 0x03 | FileBothDirectoryInformation | + short name (8.3) — **most commonly used** |
| 0x25 | FileIdBothDirectoryInformation | + file ID — **also very common** |

Each entry in the buffer contains: NextEntryOffset, FileIndex, timestamps, sizes, attributes, filename.

### FLUSH (0x0007)

Flushes write buffers. Simple FileId-based request.

### IOCTL (0x000B)

Pass-through I/O control. Many subtypes. For a minimal server, key ones:

- `FSCTL_VALIDATE_NEGOTIATE_INFO` (0x00140204) — SMB 3.x secure negotiate validation. **Must handle to avoid connection drops.**
- `FSCTL_PIPE_TRANSCEIVE` — named pipe operations (not needed for file shares)
- `FSCTL_DFS_GET_REFERRALS` — DFS referrals (return STATUS_NOT_FOUND)

### CANCEL (0x000C)

Cancels a pending async request. No response expected.

### ECHO (0x000D)

Keep-alive. Simple request → response.

### LOCK (0x000A)

Byte-range locks on files. See [§8 Locking Model](#8-locking-model).

### CHANGE_NOTIFY (0x000F)

Watches for filesystem changes. Async — response sent when change occurs. Can be deferred initially (return STATUS_NOT_SUPPORTED).

---

## 7. File Handle Model

### FileId

A FileId is 16 bytes: 8-byte Persistent + 8-byte Volatile.

```
┌────────────────────────────┐
│ Persistent (8 bytes)       │  ← Survives reconnect (SMB 3.x durable handles)
│ Volatile (8 bytes)         │  ← Connection-scoped
└────────────────────────────┘
```

For a simple server, use the same value for both halves. Generate a unique 8-byte ID per open.

### File Handle Lifecycle

1. **CREATE** opens a handle → returns FileId
2. **READ/WRITE/QUERY_INFO/SET_INFO/FLUSH/LOCK** use the FileId
3. **CLOSE** releases the handle

The server must maintain a mapping: `FileId → { path, access_mode, position, etc. }`

### FILETIME Format

SMB uses Windows FILETIME: 64-bit unsigned integer representing 100-nanosecond intervals since January 1, 1601 UTC.

```ruby
# Ruby Time → FILETIME
EPOCH_DIFF = 116444736000000000  # 100ns intervals between 1601-01-01 and 1970-01-01
def time_to_filetime(time)
  (time.to_i * 10_000_000) + (time.nsec / 100) + EPOCH_DIFF
end

# FILETIME → Ruby Time
def filetime_to_time(ft)
  unix_100ns = ft - EPOCH_DIFF
  Time.at(unix_100ns / 10_000_000, (unix_100ns % 10_000_000) * 100, :nanosecond)
end
```

---

## 8. Locking Model

### Byte-Range Locks

SMB2 LOCK command provides byte-range locking on open files.

**Lock types:**
- Shared read lock — multiple readers, no writers
- Exclusive write lock — one owner, no other access

**For samba-dave:** Byte-range locks are rarely used by GUI clients (Finder, Explorer). They're mostly used by applications like Office for file co-editing. **Can be deferred to a later phase.** Return `STATUS_NOT_SUPPORTED` for LOCK initially.

### Opportunistic Locks (Oplocks)

Oplocks allow clients to cache file data locally for performance. The server grants an oplock; if another client accesses the file, the server sends an OPLOCK_BREAK to the first client.

**Oplock levels:**
- Level II (shared read cache)
- Exclusive (exclusive read+write cache)
- Batch (exclusive + handle caching)
- Lease (SMB 3.x — per-file or per-directory, survives handle close)

**For samba-dave:** Oplocks are a performance optimisation, not a correctness requirement. **Skip initially.** Return no oplock granted in CREATE responses (OplockLevel = 0x00 = NONE). Clients will work fine without them — just slightly slower due to no caching.

### What Clients Actually Need

Windows Explorer and macOS Finder work fine without oplocks or byte-range locks. They might request them, but gracefully handle denial. The critical path is: CREATE → READ/WRITE → CLOSE.

---

## 9. Authentication — NTLM Wire Format

### App-Specific Password Pattern

samba-dave uses **app-generated credentials** rather than AD/domain integration:

1. The host application (e.g., Rails) generates a UUID username + random password per user
2. User enters these once when mounting the share; OS saves in keychain/credential manager
3. samba-dave validates against the app's credential store via a pluggable SecurityProvider
4. NTLM is just the **wire format** — we control both the credential and the validation

This means: no Active Directory, no Kerberos, no domain controller. Just challenge-response using a known plaintext password.

### NTLM Challenge-Response Flow

NTLM authentication happens inside SESSION_SETUP, wrapped in SPNEGO/GSS-API:

```
Round 1:
  Client → NEGOTIATE_MESSAGE (Type 1)
    Contains: flags, domain hint, workstation name
  
  Server → CHALLENGE_MESSAGE (Type 2)
    Contains: flags, server challenge (8 random bytes), target name, target info
    Status: STATUS_MORE_PROCESSING_REQUIRED (0xC0000016)

Round 2:
  Client → AUTHENTICATE_MESSAGE (Type 3)
    Contains: LM response, NT response, domain, user, workstation, encrypted session key
  
  Server → validates response, returns STATUS_SUCCESS or STATUS_LOGON_FAILURE
```

### Server-Side NTLM Validation (with known password)

Since we know the user's plaintext password (from the app's credential store):

1. **Receive Type 1** — extract client flags
2. **Generate Type 2** — generate 8 random bytes as server challenge, set target info
3. **Receive Type 3** — extract username, NT response, client challenge
4. **Validate** — compute the expected NT response using the known password + server challenge, compare with received response

```ruby
# NTLMv2 validation pseudocode (simplified)
def validate_ntlmv2(username, password, server_challenge, nt_response, client_blob)
  # Step 1: Compute NTHash = MD4(UTF16LE(password))
  nt_hash = OpenSSL::Digest::MD4.digest(password.encode("UTF-16LE"))
  
  # Step 2: Compute NTLMv2 hash = HMAC_MD5(NTHash, UPPER(username) + domain)
  v2_hash = OpenSSL::HMAC.digest("MD5", nt_hash, (username.upcase + domain).encode("UTF-16LE"))
  
  # Step 3: Compute expected response = HMAC_MD5(v2_hash, server_challenge + client_blob)
  expected = OpenSSL::HMAC.digest("MD5", v2_hash, server_challenge + client_blob)
  
  # Step 4: Compare first 16 bytes of nt_response with expected
  nt_response[0, 16] == expected
end
```

### SPNEGO Wrapping

NTLM tokens are wrapped in SPNEGO (Simple and Protected GSSAPI Negotiation):

- **Type 1** is wrapped in `NegTokenInit` (OID: 1.3.6.1.4.1.311.2.2.10 for NTLMSSP)
- **Type 2** is wrapped in `NegTokenResp` (responseToken)
- **Type 3** is wrapped in `NegTokenResp` (responseToken)

The `rubyntlm` gem handles Type 1/2/3 message creation and parsing. SPNEGO is ASN.1/DER encoded — we'll need to handle the wrapping/unwrapping ourselves or use a small ASN.1 library.

### Key Gem: rubyntlm

- **Gem:** `rubyntlm` (WinRb/rubyntlm on GitHub)
- **Supports:** NTLM v1 and v2
- **Provides:** `Net::NTLM::Message::Type1`, `Type2`, `Type3` — message creation and parsing
- **Used by:** ruby_smb, WinRM, and other Ruby Windows integration libraries
- **License:** MIT

### What We Build vs What We Borrow

| Component | Build or Borrow |
|-----------|----------------|
| NTLM Type 1/2/3 parsing | Borrow from `rubyntlm` |
| SPNEGO wrapping/unwrapping | Build (small ASN.1 DER encoder/decoder) OR borrow from `ruby_smb` |
| NTLMv2 response validation | Build (using OpenSSL for HMAC-MD5, MD4) |
| Credential lookup | Delegate to SecurityProvider interface |
| Session key derivation | Build (for signing support) |

---

## 10. Status Codes

SMB2 uses NT Status codes (32-bit). Key ones for a file server:

| Code | Name | Meaning |
|------|------|---------|
| 0x00000000 | STATUS_SUCCESS | Operation succeeded |
| 0xC0000016 | STATUS_MORE_PROCESSING_REQUIRED | Auth in progress (multi-round NTLM) |
| 0xC0000022 | STATUS_ACCESS_DENIED | Permission denied |
| 0xC000000F | STATUS_NO_SUCH_FILE | File not found |
| 0xC0000034 | STATUS_OBJECT_NAME_NOT_FOUND | Path component not found |
| 0xC000003A | STATUS_OBJECT_PATH_NOT_FOUND | Directory in path not found |
| 0xC0000035 | STATUS_OBJECT_NAME_COLLISION | File already exists |
| 0xC00000BA | STATUS_FILE_IS_A_DIRECTORY | Expected file, got directory |
| 0xC00000FB | STATUS_NOT_A_DIRECTORY | Expected directory, got file |
| 0xC0000043 | STATUS_SHARING_VIOLATION | File in use by another client |
| 0xC000006D | STATUS_LOGON_FAILURE | Authentication failed |
| 0xC0000002 | STATUS_NOT_IMPLEMENTED | Command not supported |
| 0xC0000003 | STATUS_INVALID_INFO_CLASS | Unknown info class |
| 0xC0000010 | STATUS_INVALID_DEVICE_REQUEST | Invalid IOCTL |
| 0xC000000D | STATUS_INVALID_PARAMETER | Bad request parameter |
| 0xC0000008 | STATUS_INVALID_HANDLE | Bad FileId |
| 0x80000005 | STATUS_BUFFER_OVERFLOW | Response truncated (not an error — more data available) |
| 0x80000006 | STATUS_NO_MORE_FILES | End of directory listing |
| 0xC00000CC | STATUS_BAD_NETWORK_NAME | Share not found |

---

## 11. What a Minimal Server Must Implement

### Minimum Viable SMB2 Server (mountable from Windows/macOS)

To be mountable as a network drive, the server must handle:

**Connection & Auth:**
1. ✅ TCP listener on port 445
2. ✅ NEGOTIATE — accept dialect, return server GUID + security blob
3. ✅ SESSION_SETUP — NTLM challenge-response (2 rounds)
4. ✅ TREE_CONNECT — accept share path, return TreeId

**File Operations:**
5. ✅ CREATE — open files and directories, return FileId
6. ✅ CLOSE — close FileId
7. ✅ READ — read file data
8. ✅ WRITE — write file data
9. ✅ QUERY_INFO — file metadata (at least FileBasicInformation, FileStandardInformation, FileNetworkOpenInformation) and filesystem metadata (FileFsVolumeInformation, FileFsSizeInformation, FileFsAttributeInformation, FileFsFullSizeInformation)
10. ✅ SET_INFO — set file timestamps/attributes (at least FileBasicInformation, FileDispositionInformation, FileRenameInformation)
11. ✅ QUERY_DIRECTORY — directory listing (FileBothDirectoryInformation or FileIdBothDirectoryInformation)

**Housekeeping:**
12. ✅ ECHO — respond to keep-alive
13. ✅ TREE_DISCONNECT — clean up tree connect
14. ✅ LOGOFF — clean up session
15. ✅ CANCEL — cancel pending operations

**Stubs (return STATUS_NOT_SUPPORTED or handle minimally):**
16. ⬜ LOCK — return STATUS_NOT_SUPPORTED initially
17. ⬜ IOCTL — handle FSCTL_VALIDATE_NEGOTIATE_INFO (required for SMB 3.x); return STATUS_NOT_SUPPORTED for others
18. ⬜ CHANGE_NOTIFY — return STATUS_NOT_SUPPORTED initially
19. ⬜ OPLOCK_BREAK — not sent by server initially (no oplocks granted)
20. ⬜ FLUSH — accept and no-op (data is already written)

### What Clients Send on Mount

When Windows Explorer mounts `\\server\share`:
1. NEGOTIATE → SESSION_SETUP (×2) → TREE_CONNECT
2. QUERY_INFO (FileFsVolumeInformation, FileFsAttributeInformation, FileFsSizeInformation)
3. CREATE of root directory → QUERY_INFO → QUERY_DIRECTORY → CLOSE
4. Various CHANGE_NOTIFY requests (async — can timeout)

When macOS Finder mounts `smb://server/share`:
1. Same connection setup
2. IOCTL (FSCTL_VALIDATE_NEGOTIATE_INFO) — **must handle for SMB 3.x**
3. Various CREATE/QUERY_INFO/QUERY_DIRECTORY cycles
4. Finder probes for `.DS_Store`, `._*` files (resource forks)

---

## 12. Existing Ruby/Python Libraries

### ruby_smb (Rapid7)

- **URL:** github.com/rapid7/ruby_smb
- **License:** BSD-3-Clause (compatible with MIT — can reference, can't copy wholesale)
- **What it is:** Full SMB1+SMB2 client library, part of the Metasploit ecosystem
- **Useful for samba-dave:**
  - **BinData packet definitions** — complete SMB2 header, all command request/response structures. These are declarative (BinData DSL) and well-tested.
  - **NTLM handling** — wraps `rubyntlm` for auth
  - **Constants** — all SMB2 command codes, status codes, flags, info classes
  - **Architecture pattern** — how they organise packets (one class per command)
- **What we can reuse:**
  - Study packet structure definitions for reference (BSD-3 allows this)
  - The BinData approach to defining wire format structures
  - Cannot copy code directly without BSD-3 attribution; better to write our own using their structures as reference
- **What we can't reuse:**
  - It's a client library — no server-side logic
  - Heavy dependency chain (bindata, rubyntlm, openssl, etc.)
- **Dependencies:** bindata, rubyntlm, openssl, windows_error

### rubyntlm (WinRb)

- **URL:** github.com/WinRb/rubyntlm
- **License:** MIT
- **What it is:** NTLM message creator and parser
- **Useful for samba-dave:**
  - `Net::NTLM::Message::Type1` — parse client negotiate messages
  - `Net::NTLM::Message::Type2` — create server challenge messages
  - `Net::NTLM::Message::Type3` — parse client authenticate messages
  - NTLMv2 hash computation utilities
- **Can we use as dependency?** Yes — MIT licensed, lightweight, actively maintained. **Recommended.**

### ruby-ntlm (macks)

- **URL:** github.com/macks/ruby-ntlm
- **License:** MIT
- **What it is:** Older NTLM client library. NTLMv1 only. **Not recommended — use rubyntlm instead.**

### impacket (Python — reference implementation)

- **URL:** github.com/fortra/impacket
- **License:** Apache 2.0 (modified)
- **What it is:** Python library for network protocols, includes a complete SMB server
- **Useful for samba-dave (as reference):**
  - `impacket/smbserver.py` — full SMB1+SMB2 server implementation (~5000 lines)
  - Architecture: `SimpleSMBServer` class wraps a `SocketServer.ThreadingTCPServer`
  - Each SMB2 command handled by `SMB2Commands.smb2XxxHandler()` static methods
  - Uses `impacket.smb2.SMB2Packet` for wire format (custom struct library, similar to BinData)
  - NTLM auth handled inline — generates challenge, validates response
  - Share management: simple dict mapping share name → local path
  - File handle tracking: dict mapping FileId → open file descriptor
- **Key architectural insights from impacket:**
  - Single-threaded per connection (threading at connection level)
  - Command dispatch is a simple dict: `{command_code: handler_function}`
  - FileId generation: random 16 bytes per open
  - Directory listing: builds full listing in memory, returns in chunks
  - IOCTL handler: only handles a few FSCTLs, returns STATUS_NOT_SUPPORTED for rest
- **Limitations:**
  - Python-specific patterns don't translate directly to Ruby
  - Tightly coupled to impacket's own struct library
  - Not designed for embedding in web apps

### Other Notable References

- **Samba** (C) — The canonical open-source SMB server. Too complex for reference but useful for understanding edge cases.
- **SMB::Server (Perl)** — `SMB::Auth` module on CPAN has NTLM server-side code. Useful reference for auth flow.
- **fusesmb** — FUSE-based SMB mount. Shows what clients expect.

---

## Appendix: Wire Format Quick Reference

### String Encoding
- All strings: UTF-16LE (2 bytes per character)
- File paths: backslash-separated on the wire (`folder\file.txt`)
- Path lengths in bytes, not characters

### Alignment
- Structures are generally 8-byte aligned
- String buffers are 2-byte aligned
- The SMB2 header is always 64 bytes

### Byte Order
- All multi-byte fields: **little-endian**
- Exception: NetBIOS frame length (4 bytes, big-endian)

### File Attributes (bit flags)
| Value | Attribute |
|-------|-----------|
| 0x00000010 | DIRECTORY |
| 0x00000020 | ARCHIVE |
| 0x00000080 | NORMAL |
| 0x00000001 | READONLY |
| 0x00000002 | HIDDEN |
| 0x00000004 | SYSTEM |

### Access Mask (common values)
| Value | Meaning |
|-------|---------|
| 0x00000001 | FILE_READ_DATA / FILE_LIST_DIRECTORY |
| 0x00000002 | FILE_WRITE_DATA / FILE_ADD_FILE |
| 0x00000004 | FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY |
| 0x00000080 | FILE_READ_ATTRIBUTES |
| 0x00000100 | FILE_WRITE_ATTRIBUTES |
| 0x00010000 | DELETE |
| 0x00020000 | READ_CONTROL |
| 0x00100000 | SYNCHRONIZE |
| 0x001F01FF | FILE_ALL_ACCESS |
| 0x80000000 | GENERIC_READ |
| 0xC0000000 | GENERIC_READ + GENERIC_WRITE |
| 0x02000000 | MAXIMUM_ALLOWED |
