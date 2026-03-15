# samba-dave — Implementation Plan

> SMB2 file server gem for the Dave multi-protocol document server platform.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Mono-Repo Placement](#2-mono-repo-placement)
3. [Provider Interface Compatibility](#3-provider-interface-compatibility)
4. [TCP Server Architecture](#4-tcp-server-architecture)
5. [Authentication Architecture](#5-authentication-architecture)
6. [Gem Structure](#6-gem-structure)
7. [Dialect Strategy](#7-dialect-strategy)
8. [What to Take from ruby_smb](#8-what-to-take-from-ruby_smb)
9. [Testing Strategy](#9-testing-strategy)
10. [Shared Compliance Testing](#10-shared-compliance-testing)
11. [Development Phases](#11-development-phases)
12. [Phase 1 Sprint Tasks](#12-phase-1-sprint-tasks)

---

## 1. Overview

samba-dave is an SMB2 file server that shares the same pluggable provider architecture as dave-server (WebDAV). One `FileSystemProvider` implementation (e.g., `C8OFileSystemProvider`) works for both protocols — write once, serve via WebDAV and SMB.

```
┌──────────────────────────────────────────────────────┐
│              Dave Platform                            │
│                                                      │
│  ┌─────────────┐          ┌─────────────────┐        │
│  │ dave-server  │          │  samba-dave      │        │
│  │ (Rack/HTTP)  │          │  (TCP/SMB2)      │        │
│  │ Port 80/443  │          │  Port 445        │        │
│  └──────┬───────┘          └──────┬───────────┘        │
│         │                         │                    │
│         └────────┬────────────────┘                    │
│                  │                                     │
│         ┌────────▼────────┐                            │
│         │ FileSystem      │  ← Same interface!         │
│         │ Provider        │                            │
│         └────────┬────────┘                            │
│                  │                                     │
│         ┌────────▼────────┐                            │
│         │ Security        │  ← Same interface!         │
│         │ Provider        │                            │
│         └─────────────────┘                            │
└──────────────────────────────────────────────────────┘
```

### Design Goals

1. **Provider compatibility** — reuse `Dave::FileSystemInterface` and `Dave::SecurityInterface`
2. **Embeddable** — start an SMB server from Ruby code, just like `Dave::Server` for WebDAV
3. **Minimal viable** — mount from Windows Explorer and macOS Finder
4. **No AD/Kerberos** — app-specific password pattern only
5. **Protocol isolation** — all SMB2 wire format knowledge contained within samba-dave

---

## 2. Mono-Repo Placement

```
dave/
├── AGENTS.md
├── CLAUDE.md                    → AGENTS.md
├── README.md
├── Gemfile                      ← add samba-dave path reference
├── docs/
│   ├── WEBDAV-SPEC.md
│   ├── SMB-SPEC.md              ← NEW (protocol reference)
│   ├── IMPLEMENTATION-PLAN.md   ← existing (WebDAV)
│   ├── SAMBA-DAVE-IMPLEMENTATION-PLAN.md  ← NEW (this file)
│   └── ARCHITECTURE.md          ← UPDATED (multi-protocol)
├── dave-server/                 (existing — WebDAV, Rack)
├── dave-filesystem/             (existing — shared provider)
├── dave-security/               (existing — shared provider)
└── samba-dave/                  ← NEW
    ├── samba-dave.gemspec
    ├── Gemfile
    ├── README.md
    ├── lib/
    │   └── samba_dave/
    │       ├── server.rb              ← TCP server + connection handler
    │       ├── connection.rb          ← Per-connection state machine
    │       ├── session.rb             ← Session state (authenticated user)
    │       ├── tree_connect.rb        ← Mounted share state
    │       ├── open_file.rb           ← Open file handle state
    │       ├── authenticator.rb       ← NTLM challenge-response + provider bridge
    │       ├── protocol/
    │       │   ├── header.rb          ← SMB2 header pack/unpack
    │       │   ├── constants.rb       ← Command codes, status codes, flags
    │       │   ├── transport.rb       ← TCP framing (4-byte length prefix)
    │       │   └── commands/
    │       │       ├── negotiate.rb
    │       │       ├── session_setup.rb
    │       │       ├── tree_connect.rb
    │       │       ├── create.rb
    │       │       ├── close.rb
    │       │       ├── read.rb
    │       │       ├── write.rb
    │       │       ├── query_info.rb
    │       │       ├── set_info.rb
    │       │       ├── query_directory.rb
    │       │       ├── flush.rb
    │       │       ├── echo.rb
    │       │       ├── ioctl.rb
    │       │       ├── lock.rb         ← stub (STATUS_NOT_SUPPORTED)
    │       │       ├── cancel.rb
    │       │       ├── logoff.rb
    │       │       └── tree_disconnect.rb
    │       └── ntlm/
    │           ├── spnego.rb          ← SPNEGO/GSS-API wrapping
    │           └── challenge.rb       ← Server challenge generation + validation
    └── spec/
        ├── spec_helper.rb
        ├── samba_dave/
        │   ├── server_spec.rb
        │   ├── connection_spec.rb
        │   ├── authenticator_spec.rb
        │   └── protocol/
        │       ├── header_spec.rb
        │       ├── transport_spec.rb
        │       └── commands/
        │           ├── negotiate_spec.rb
        │           ├── session_setup_spec.rb
        │           ├── create_spec.rb
        │           ├── read_spec.rb
        │           ├── write_spec.rb
        │           ├── query_info_spec.rb
        │           ├── query_directory_spec.rb
        │           └── ...
        └── integration/
            ├── mount_spec.rb          ← smbclient-based integration tests
            └── file_operations_spec.rb
```

---

## 3. Provider Interface Compatibility

### FileSystemInterface — Works As-Is

The existing `Dave::FileSystemInterface` maps cleanly to SMB2 operations:

| SMB2 Command | FileSystemInterface Method |
|-------------|---------------------------|
| CREATE (open existing) | `get_resource(path)` to check existence |
| CREATE (create new file) | `write_content(path, empty_io)` |
| CREATE (create directory) | `create_collection(path)` |
| CLOSE | No-op (no persistent handles in provider) |
| READ | `read_content(path)` |
| WRITE | `write_content(path, io)` |
| QUERY_INFO (file) | `get_resource(path)` → `Dave::Resource` |
| QUERY_INFO (filesystem) | `quota_available_bytes`, `quota_used_bytes` |
| SET_INFO (rename) | `move(src, dst)` |
| SET_INFO (delete) | `delete(path)` |
| SET_INFO (timestamps) | Not currently in interface — see Extensions below |
| QUERY_DIRECTORY | `list_children(path)` → `Array<Dave::Resource>` |
| FLUSH | No-op (provider writes are synchronous) |

### Required Extensions

The current interface needs small additions for full SMB compatibility:

#### 1. Timestamp Modification (optional)

SMB SET_INFO can set file timestamps (creation, modification, access). The current interface doesn't support this. **This is a nice-to-have, not blocking.** Clients generally don't fail if timestamp setting is silently ignored.

```ruby
# Proposed addition to Dave::FileSystemInterface (optional for providers)
def set_timestamps(path, created_at: nil, last_modified: nil)
  # Default: no-op (silently ignore)
end

def supports_timestamps? = false
```

#### 2. File Attribute Setting (optional)

SMB files have attributes (hidden, readonly, archive, system). The current interface doesn't model these. **Also nice-to-have.** Return `FILE_ATTRIBUTE_NORMAL` for files and `FILE_ATTRIBUTE_DIRECTORY` for collections.

### What Doesn't Map

| SMB2 Feature | FileSystemInterface Gap | Workaround |
|-------------|------------------------|------------|
| File handles | Provider is stateless | samba-dave manages handles internally |
| Byte-range locks | Not in provider | samba-dave manages locks internally (like LockManager in dave-server) |
| File sharing modes | Not in provider | samba-dave tracks sharing state per open |
| Extended attributes | Dead properties (different format) | Not needed initially |
| NTFS streams | Not supported | Return empty stream info |
| Security descriptors | Not applicable | Return minimal SD |

### Handle Layer

samba-dave adds a **handle layer** between the SMB protocol and the provider:

```
SMB2 CREATE Request
       │
       ▼
┌──────────────────┐
│  OpenFile         │  ← samba-dave tracks: path, access mode, file position
│  (Handle Layer)   │     generates FileId, manages sharing violations
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  FileSystem       │  ← Stateless provider, same as WebDAV uses
│  Provider         │
└──────────────────┘
```

The `SambaDave::OpenFile` object holds:
- `file_id` — 16-byte handle returned to client
- `path` — resource path in the provider
- `access_mask` — what operations are allowed
- `share_access` — sharing mode
- `position` — current read/write offset
- `tree_connect` — parent tree connect reference

### SecurityInterface — Works As-Is (with Adapter)

The existing `Dave::SecurityInterface` is HTTP-oriented (`authenticate(request)` takes a Rack request). samba-dave needs a simpler interface: `authenticate(username, password)`.

Two options:

**Option A: Adapter pattern** (recommended)
```ruby
# samba-dave wraps the security provider
module SambaDave
  class SecurityAdapter
    def initialize(security_provider)
      @provider = security_provider
    end
    
    def authenticate(username, password)
      # Build a synthetic Rack request with Basic auth
      request = build_rack_request(username, password)
      @provider.authenticate(request)
    end
    
    def authorize(principal, path, operation)
      @provider.authorize(principal, path, operation)
    end
  end
end
```

**Option B: Extend SecurityInterface** (if adapter is too clunky)
```ruby
# Add to Dave::SecurityInterface
def authenticate_credentials(username, password)
  raise NotImplementedError
end
```

**Decision: Option A (Adapter).** It keeps the interface clean and doesn't force WebDAV-only providers to implement SMB-specific methods. The adapter is trivial.

---

## 4. TCP Server Architecture

### Why Not Rack

SMB2 is a binary protocol over raw TCP. It cannot be served through Rack, HTTP, or any web framework middleware. samba-dave needs its own TCP server.

### Server Design

```ruby
module SambaDave
  class Server
    def initialize(filesystem:, security: nil, share_name: "share", port: 445)
      @filesystem = filesystem
      @security = security
      @share_name = share_name
      @port = port
      @server_guid = SecureRandom.bytes(16)
      @connections = Concurrent::Map.new  # thread-safe connection tracking
    end
    
    def start
      @tcp_server = TCPServer.new("0.0.0.0", @port)
      loop do
        client = @tcp_server.accept
        Thread.new(client) { |sock| handle_connection(sock) }
      end
    end
    
    def stop
      @tcp_server&.close
      @connections.each_value(&:close)
    end
    
    private
    
    def handle_connection(socket)
      connection = Connection.new(socket, self)
      @connections[connection.id] = connection
      connection.run  # blocking — reads messages until disconnect
    ensure
      @connections.delete(connection.id)
      socket.close rescue nil
    end
  end
end
```

### Connection State Machine

```
┌─────────┐
│ INITIAL │──── NEGOTIATE ────▶┌────────────┐
└─────────┘                    │ NEGOTIATED │
                               └─────┬──────┘
                                     │
                              SESSION_SETUP
                                     │
                                     ▼
                               ┌────────────────┐
                               │ AUTHENTICATED   │
                               └─────┬──────────┘
                                     │
                              TREE_CONNECT
                                     │
                                     ▼
                               ┌────────────────┐
                               │ CONNECTED       │──── File operations
                               └────────────────┘
```

### Threading Model

- **One thread per connection** — simple, sufficient for our use case
- Thread-safety: each `Connection` has its own state; shared state (open files across sessions) protected by mutex
- Alternative for future: use `Async` gem for event-driven I/O (lower resource usage)

### Embedding in Rails

```ruby
# config/initializers/smb_server.rb
Thread.new do
  SambaDave::Server.new(
    filesystem: C8OFileSystemProvider.new,
    security: C8OSecurityProvider.new,
    share_name: "documents",
    port: 445
  ).start
end
```

Or run as a standalone process:
```ruby
# bin/smb_server
require "samba_dave/server"
server = SambaDave::Server.new(
  filesystem: Dave::FileSystemProvider.new(root: "/var/shares"),
  security: Dave::SecurityConfiguration.new(config_path: "security.yml"),
  share_name: "files"
)
server.start
```

### Port 445 Considerations

Port 445 requires root/elevated privileges on Unix. Options:
1. Run as root (not recommended for production)
2. Use `setcap` to grant capability: `sudo setcap 'cap_net_bind_service=+ep' $(which ruby)`
3. Use iptables/nftables to redirect from 445 to a high port
4. Run behind a reverse proxy/load balancer that handles port 445
5. Use a high port (e.g., 4450) for development/testing — clients can specify port in UNC path

---

## 5. Authentication Architecture

### App-Specific Password Pattern

samba-dave uses **app-generated credentials** rather than Active Directory integration:

```
┌──────────────────┐     ┌────────────────────┐
│  Rails App        │     │  samba-dave Server   │
│                   │     │                      │
│  User Dashboard:  │     │  NTLM Auth:          │
│  "Your SMB creds" │     │  1. Receive Type 1   │
│  Username: uuid   │     │  2. Send Challenge   │
│  Password: random │     │  3. Receive Type 3   │
│                   │     │  4. Extract username  │
│  Stored in DB:    │     │  5. Call provider:    │
│  users.smb_user   │────▶│     authenticate(     │
│  users.smb_pass   │     │       username,       │
│  (bcrypt hash)    │     │       password)        │
│                   │     │  6. Provider validates │
└──────────────────┘     └────────────────────┘
```

### How It Works

1. **Rails app** generates per-user SMB credentials:
   - Username: UUID (e.g., `a1b2c3d4-e5f6-7890-abcd-ef1234567890`)
   - Password: random string (e.g., `xK9mP2nQ7rS4tU8v`)
   - Stored against user record in app DB

2. **User mounts share** in Finder/Explorer:
   - `smb://server/share` (macOS) or `\\server\share` (Windows)
   - Enters UUID username + random password
   - OS saves in keychain/credential manager — one-time setup

3. **samba-dave receives NTLM auth:**
   - NTLM is just the wire format — challenge-response handshake
   - Server generates challenge, client responds with hashed password
   - Since we know the plaintext password (from DB), we can compute the expected response and compare

4. **SecurityProvider validates:**
   - `authenticate(username, password)` → returns `Dave::Principal` or `nil`
   - Once authenticated, principal identity flows through to filesystem provider for permission checks

### Authentication Flow (Detailed)

```ruby
module SambaDave
  class Authenticator
    def initialize(security_provider)
      @provider = security_provider
      @pending_challenges = {}  # session_id → { challenge:, timestamp: }
    end
    
    # Called on first SESSION_SETUP (Type 1 received)
    def begin_auth(session_id, type1_message)
      server_challenge = SecureRandom.bytes(8)
      @pending_challenges[session_id] = {
        challenge: server_challenge,
        timestamp: Time.now
      }
      
      # Build Type 2 (CHALLENGE) message
      build_challenge_message(server_challenge, type1_message)
    end
    
    # Called on second SESSION_SETUP (Type 3 received)
    def complete_auth(session_id, type3_message)
      pending = @pending_challenges.delete(session_id)
      return nil unless pending
      
      username = type3_message.user
      domain = type3_message.domain
      
      # Extract the password from the NTLM response
      # Since we control the credential store, we look up the user's
      # plaintext password and validate the NTLMv2 response ourselves
      
      # The provider gives us the password for this username
      # (or nil if unknown user)
      @provider.authenticate_credentials(username, type3_message, pending[:challenge])
    end
  end
end
```

### NTLMv2 Validation

The critical insight: since we store the user's password (or its NT hash), we can validate the NTLMv2 response server-side:

```ruby
def validate_ntlmv2(username, password, server_challenge, nt_response)
  # nt_response = NTProofStr (16 bytes) + ClientChallenge (variable blob)
  nt_proof_str = nt_response[0, 16]
  client_blob = nt_response[16..]
  
  # Compute NTHash
  nt_hash = OpenSSL::Digest::MD4.digest(password.encode("UTF-16LE"))
  
  # Compute NTLMv2 hash
  identity = (username.upcase).encode("UTF-16LE")
  v2_hash = OpenSSL::HMAC.digest("MD5", nt_hash, identity)
  
  # Compute expected NTProofStr
  expected = OpenSSL::HMAC.digest("MD5", v2_hash, server_challenge + client_blob)
  
  # Constant-time comparison
  OpenSSL.fixed_length_secure_compare(expected, nt_proof_str)
end
```

**Note on domain:** In the app-password pattern, there is no domain. The username is the full identity. Clients may send a domain field (their workstation name or "." for local) — we ignore it and match on username alone.

### SecurityProvider for SMB

```ruby
# Example provider for a Rails app
class C8OSmBSecurityProvider
  # Authenticate using app-generated credentials
  # Returns Dave::Principal or nil
  def authenticate_credentials(username, password)
    user = User.find_by(smb_username: username)
    return nil unless user
    return nil unless user.smb_password_valid?(password)
    
    Dave::Principal.new(id: user.id, display_name: user.name)
  end
  
  # Authorize access to a path
  def authorize(principal, path, operation)
    # App-specific permission logic
    user = User.find(principal.id)
    user.can_access_path?(path, operation)
  end
  
  # Challenge string (not used for SMB — NTLM handled internally)
  def challenge
    "NTLM"
  end
end
```

### What rubyntlm Handles

The `rubyntlm` gem (MIT license) handles the NTLM message format:

| Task | rubyntlm Support |
|------|-------------------|
| Parse Type 1 (NEGOTIATE) | `Net::NTLM::Message.parse(blob)` |
| Build Type 2 (CHALLENGE) | `Net::NTLM::Message::Type2.new(...)` |
| Parse Type 3 (AUTHENTICATE) | `Net::NTLM::Message.parse(blob)` |
| NTLMv2 hash computation | `Net::NTLM.ntlmv2_hash(...)` |
| NT hash (MD4) | `Net::NTLM.ntlm_hash(password)` |

### What We Build

| Component | Implementation |
|-----------|---------------|
| SPNEGO wrapping/unwrapping | Minimal ASN.1 DER encoder/decoder (~100 lines) |
| NTLMv2 response validation | ~30 lines using OpenSSL |
| Challenge generation | `SecureRandom.bytes(8)` |
| SecurityProvider adapter | Bridges to `Dave::SecurityInterface` |
| Credential management | App-side (not samba-dave's responsibility) |

### Kerberos / AD — Out of Scope

Not implemented. Not planned. The app-specific password pattern eliminates the need:
- No domain controller communication
- No service tickets
- No SPNs
- No keytabs
- Massively simpler implementation and deployment

---

## 6. Gem Structure

### samba-dave.gemspec

```ruby
Gem::Specification.new do |spec|
  spec.name          = "samba-dave"
  spec.version       = "0.1.0"
  spec.authors       = ["Dave"]
  spec.summary       = "SMB2 file server using Dave provider interfaces"
  spec.require_paths = ["lib"]
  spec.files         = Dir["lib/**/*.rb"]
  spec.required_ruby_version = ">= 4.0"

  spec.add_dependency "dave-server"      # For interface definitions and Dave::Resource
  spec.add_dependency "rubyntlm", "~> 0.6"  # NTLM message handling
  spec.add_dependency "bindata", "~> 2.5"   # Binary struct definitions

  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "simplecov"
end
```

### Key Dependencies

| Gem | Purpose | License |
|-----|---------|---------|
| `dave-server` | `Dave::FileSystemInterface`, `Dave::Resource`, error classes | MIT |
| `rubyntlm` | NTLM Type 1/2/3 message handling | MIT |
| `bindata` | SMB2 packet structure definitions (binary wire format) | Ruby |
| `openssl` | HMAC-MD5, MD4 for NTLMv2 validation (stdlib) | Ruby |

### Why BinData

The SMB2 protocol is a binary format with complex nested structures. BinData provides:
- Declarative DSL for defining binary structures
- Automatic endianness handling (SMB2 is little-endian)
- Read/write from binary strings
- Used successfully by ruby_smb for the same purpose

Example:
```ruby
class Smb2Header < BinData::Record
  endian :little
  string :protocol_id, length: 4, value: "\xFESMB"
  uint16 :structure_size, value: 64
  uint16 :credit_charge
  uint32 :status
  uint16 :command
  uint16 :credit_request_response
  uint32 :flags
  uint32 :next_command
  uint64 :message_id
  uint32 :reserved
  uint32 :tree_id
  uint64 :session_id
  string :signature, length: 16
end
```

---

## 7. Dialect Strategy

### Recommended Approach: Progressive Dialect Support

| Phase | Dialects | Compatibility |
|-------|----------|---------------|
| Phase 1-3 | SMB 2.0.2 only | Windows 10/11 ✅, macOS ✅ (negotiates down) |
| Phase 4+ | SMB 2.0.2 + 2.1 | Better performance (credit charging) |
| Phase 6+ | SMB 2.0.2 + 2.1 + 3.0.2 | Full macOS support, optional encryption |

### Why Start with 2.0.2

- **Simplest dialect** — no credit charging, no multichannel, no encryption
- **Universal compatibility** — all modern clients support it
- **No FSCTL_VALIDATE_NEGOTIATE_INFO** — only required for SMB 3.x
- **No pre-auth integrity** — only required for 3.1.1
- Lets us focus on getting file operations right before adding protocol features

### What Changes Per Dialect

| Feature | 2.0.2 | 2.1 (add later) | 3.0.2 (add later) |
|---------|-------|-----------------|-------------------|
| Credit charging | No (always 1) | Yes | Yes |
| Durable handles | No | Yes | Yes |
| Multi-credit ops | No | Yes | Yes |
| Directory leases | No | No | Yes |
| Encryption | No | No | Yes |
| Secure negotiate | No | No | Yes (FSCTL) |
| Signing required | Optional | Optional | Configurable |

---

## 8. What to Take from ruby_smb

### Reusable Concepts (reference, not copy)

ruby_smb (BSD-3-Clause) provides excellent reference material:

| What | Where in ruby_smb | How We Use It |
|------|-------------------|---------------|
| SMB2 header layout | `lib/ruby_smb/smb2/smb2_header.rb` | Reference for our BinData struct |
| Command codes | `lib/ruby_smb/smb2/commands.rb` | Copy constants (facts aren't copyrightable) |
| Status codes | `lib/ruby_smb/smb2/status_codes.rb` | Copy constants |
| Packet structures | `lib/ruby_smb/smb2/packet/` | Study field layouts, write our own BinData definitions |
| NTLM integration | `lib/ruby_smb/client/authentication.rb` | Understand SPNEGO wrapping flow |
| File info classes | `lib/ruby_smb/fscc/` | Reference for QUERY_INFO/SET_INFO structures |

### What We Write Ourselves

- All server-side logic (ruby_smb is client-only)
- Command handler dispatch
- Connection/session/tree state management
- File handle tracking
- Provider bridge layer

### BinData Approach

We'll follow ruby_smb's pattern of one BinData class per packet type, but keep it simpler:

```ruby
# Our pattern: one file per command, request + response structs
module SambaDave
  module Protocol
    module Commands
      class NegotiateRequest < BinData::Record
        endian :little
        uint16 :structure_size, value: 36
        uint16 :dialect_count
        uint16 :security_mode
        uint16 :reserved
        uint32 :capabilities
        string :client_guid, length: 16
        # ... negotiate contexts for 3.1.1
        array  :dialects, type: :uint16le, initial_length: :dialect_count
      end
      
      class NegotiateResponse < BinData::Record
        endian :little
        uint16 :structure_size, value: 65
        uint16 :security_mode
        uint16 :dialect_revision
        # ... etc
      end
    end
  end
end
```

---

## 9. Testing Strategy

### Unit Tests

Every protocol component has dedicated unit tests:

```ruby
# spec/samba_dave/protocol/header_spec.rb
RSpec.describe SambaDave::Protocol::Header do
  it "packs a valid SMB2 header" do
    header = described_class.new(command: 0x0000, message_id: 1)
    binary = header.to_binary_s
    expect(binary[0, 4]).to eq("\xFESMB")
    expect(binary.bytesize).to eq(64)
  end
  
  it "unpacks a binary SMB2 header" do
    header = described_class.read(binary_fixture("negotiate_request"))
    expect(header.command).to eq(0x0000)
  end
end
```

### Integration Tests (smbclient)

Use `smbclient` (from Samba project) for integration testing:

```ruby
# spec/integration/file_operations_spec.rb
RSpec.describe "SMB file operations", :integration do
  let(:server) { start_test_server(port: 4450) }
  
  it "lists files in root directory" do
    output = `smbclient //localhost:4450/share -U testuser%testpass -c "ls" 2>&1`
    expect(output).to include(".")
    expect(output).to include("..")
  end
  
  it "uploads and downloads a file" do
    `smbclient //localhost:4450/share -U testuser%testpass -c "put testfile.txt" 2>&1`
    output = `smbclient //localhost:4450/share -U testuser%testpass -c "get testfile.txt -" 2>&1`
    expect(output).to include("test content")
  end
end
```

### Packet-Level Tests

Test binary serialisation/deserialisation with fixtures captured from Wireshark:

```ruby
# Capture real SMB2 packets with Wireshark, save as binary fixtures
# spec/fixtures/packets/negotiate_request.bin
# spec/fixtures/packets/negotiate_response.bin

RSpec.describe SambaDave::Protocol::Commands::NegotiateRequest do
  it "parses a real negotiate request from Windows 11" do
    binary = File.binread("spec/fixtures/packets/negotiate_request.bin")
    request = described_class.read(binary)
    expect(request.dialect_count).to be > 0
    expect(request.dialects).to include(0x0202)
  end
end
```

### Manual Testing

```bash
# Mount from macOS
open smb://localhost:4450/share

# Mount from Linux
sudo mount -t cifs //localhost/share /mnt/test -o port=4450,username=test,password=test

# smbclient (interactive)
smbclient //localhost:4450/share -U testuser%testpass
```

---

## 10. Shared Compliance Testing

### Extending the Compliance Test Suite

The existing `Dave::FileSystemInterface::ComplianceTests` verify that a provider works for WebDAV. We want to extend this so the same provider is also verified for SMB use.

**Approach: Separate SMB compliance module, same pattern:**

```ruby
# Defined in samba-dave/lib/samba_dave/compliance_tests.rb
module SambaDave
  module ComplianceTests
    def self.included(base)
      base.describe "SMB Provider compliance" do
        # subject must be a configured FileSystemInterface provider

        it "supports the operations needed by SMB" do
          # CREATE file
          subject.write_content("/smb-test.txt", StringIO.new("hello"))
          resource = subject.get_resource("/smb-test.txt")
          expect(resource).not_to be_nil
          expect(resource.content_length).to eq(5)
          
          # READ file
          expect(subject.read_content("/smb-test.txt").read).to eq("hello")
          
          # QUERY_DIRECTORY (list children)
          children = subject.list_children("/")
          expect(children.map(&:path)).to include("/smb-test.txt")
          
          # RENAME (move)
          subject.move("/smb-test.txt", "/renamed.txt")
          expect(subject.get_resource("/smb-test.txt")).to be_nil
          expect(subject.get_resource("/renamed.txt")).not_to be_nil
          
          # DELETE
          subject.delete("/renamed.txt")
          expect(subject.get_resource("/renamed.txt")).to be_nil
        end

        it "provides required Resource fields for SMB" do
          subject.write_content("/meta.txt", StringIO.new("test"))
          resource = subject.get_resource("/meta.txt")
          
          expect(resource.last_modified).to be_a(Time)
          expect(resource.created_at).to be_a(Time)
          expect(resource.content_length).to be_a(Integer)
          expect(resource.etag).to be_a(String)
          expect(resource.collection?).to be false
        end

        it "supports nested directory operations for SMB" do
          subject.create_collection("/subdir/")
          subject.write_content("/subdir/file.txt", StringIO.new("nested"))
          
          children = subject.list_children("/subdir/")
          expect(children.length).to eq(1)
          expect(children.first.path).to eq("/subdir/file.txt")
        end
      end
    end
  end
end
```

### Combined Provider Testing

A provider implementer includes both:

```ruby
RSpec.describe C8OFileSystemProvider do
  subject { C8OFileSystemProvider.new(config) }
  
  include Dave::FileSystemInterface::ComplianceTests  # WebDAV
  include SambaDave::ComplianceTests                   # SMB
end
```

If both pass, the provider works for both protocols. ✅

---

## 11. Development Phases

### Phase 1: TCP Skeleton + Dialect Negotiation

**Goal:** A TCP server that accepts connections and negotiates SMB 2.0.2.

**Deliverables:**
- `SambaDave::Server` — TCP listener, thread-per-connection
- `SambaDave::Connection` — reads/writes framed SMB2 messages
- `SambaDave::Protocol::Header` — pack/unpack 64-byte SMB2 header
- `SambaDave::Protocol::Transport` — NetBIOS framing (4-byte length prefix)
- `SambaDave::Protocol::Constants` — command codes, status codes
- `SambaDave::Protocol::Commands::Negotiate` — handle NEGOTIATE request/response
- SMB1 `COM_NEGOTIATE` detection (respond with SMB2 wildcard to force re-negotiate)

**Exit criteria:** `smbclient -L //localhost:4450` shows a connection attempt and dialect negotiation (will fail at SESSION_SETUP — that's expected).

**Estimated effort:** 3-4 agent runs

---

### Phase 2: Authentication (NTLM + SPNEGO)

**Goal:** Complete NTLM authentication flow. Client can establish an authenticated session.

**Deliverables:**
- `SambaDave::Authenticator` — NTLM challenge generation + NTLMv2 validation
- `SambaDave::NTLM::SPNEGO` — SPNEGO/GSS-API token wrapping/unwrapping
- `SambaDave::NTLM::Challenge` — Type 2 message builder, Type 3 validator
- `SambaDave::Session` — session state (authenticated principal, session ID)
- `SambaDave::Protocol::Commands::SessionSetup` — handle SESSION_SETUP (2 rounds)
- `SambaDave::Protocol::Commands::Logoff` — handle LOGOFF

**Exit criteria:** `smbclient //localhost:4450/share -U user%pass` authenticates successfully and shows `smb: \>` prompt (will fail at TREE_CONNECT or file ops).

**Estimated effort:** 4-5 agent runs (NTLM is fiddly)

---

### Phase 3: Tree Connect + Directory Listing

**Goal:** Client can mount a share and browse directories.

**Deliverables:**
- `SambaDave::TreeConnect` — share state (name, path, provider reference)
- `SambaDave::Protocol::Commands::TreeConnect` — handle TREE_CONNECT/DISCONNECT
- `SambaDave::Protocol::Commands::Create` — open files and directories, return FileId
- `SambaDave::Protocol::Commands::Close` — close handles
- `SambaDave::Protocol::Commands::QueryInfo` — file and filesystem metadata
- `SambaDave::Protocol::Commands::QueryDirectory` — directory listing
- `SambaDave::OpenFile` — file handle tracking
- `SambaDave::Protocol::Commands::Echo` — keep-alive
- FileId generation and tracking

**Exit criteria:** `smbclient //localhost:4450/share -U user%pass -c "ls"` shows directory contents. macOS `open smb://localhost:4450/share` shows a Finder window with directory listing (possibly with errors on some operations).

**Estimated effort:** 5-6 agent runs

---

### Phase 4: Read/Write File Operations

**Goal:** Full read and write support. Files can be created, modified, and deleted.

**Deliverables:**
- `SambaDave::Protocol::Commands::Read` — read file data at offset
- `SambaDave::Protocol::Commands::Write` — write file data at offset
- `SambaDave::Protocol::Commands::SetInfo` — set file attributes, rename, delete-on-close
- `SambaDave::Protocol::Commands::Flush` — flush (no-op)
- `SambaDave::Protocol::Commands::Cancel` — cancel pending requests
- Large file handling (streaming, chunked reads/writes)

**Exit criteria:** Can upload, download, rename, and delete files via `smbclient` and Finder/Explorer.

```bash
smbclient //localhost:4450/share -U user%pass -c "put local.txt remote.txt"
smbclient //localhost:4450/share -U user%pass -c "get remote.txt downloaded.txt"
smbclient //localhost:4450/share -U user%pass -c "rename remote.txt renamed.txt"
smbclient //localhost:4450/share -U user%pass -c "del renamed.txt"
```

**Estimated effort:** 4-5 agent runs

---

### Phase 5: Client Compatibility + IOCTL

**Goal:** Works reliably with Windows Explorer and macOS Finder.

**Deliverables:**
- Handle IOCTL (at least `FSCTL_VALIDATE_NEGOTIATE_INFO` for SMB 3.x clients)
- Handle all QUERY_INFO classes that clients actually request
- Handle SET_INFO for timestamps and attributes
- Handle CHANGE_NOTIFY (return STATUS_NOT_SUPPORTED gracefully)
- Handle LOCK (return STATUS_NOT_SUPPORTED gracefully)
- macOS-specific: handle `._` resource fork queries, `.DS_Store` probes
- Windows-specific: handle security descriptor queries (minimal SD response)
- Fix edge cases found during real client testing

**Exit criteria:** Mount from Windows 10/11 Explorer and macOS Finder works end-to-end. Can create folders, drag-and-drop files, rename, delete. No error dialogs for basic operations.

**Estimated effort:** 5-6 agent runs

---

### Phase 6: Hardening + SMB 2.1 Dialect

**Goal:** Production-ready. Add SMB 2.1 dialect support.

**Deliverables:**
- SMB 2.1 dialect negotiation
- Credit management (proper credit charging/granting)
- Message signing (HMAC-SHA256 with session key)
- Concurrent connection stress testing
- Large file performance testing
- Error handling audit (all error paths return correct NT status codes)
- Thread safety audit
- Logging (structured request/response logging)
- Compliance tests updated for SMB 2.1 features

**Exit criteria:** Reliable under sustained use. No data corruption. Handles disconnect/reconnect gracefully.

**Estimated effort:** 4-5 agent runs

---

### Phase Summary

| Phase | Focus | Key Deliverable | Est. Effort |
|-------|-------|-----------------|-------------|
| 1 | TCP + Negotiate | Server skeleton, dialect negotiation | 3-4 runs |
| 2 | Authentication | NTLM challenge-response, sessions | 4-5 runs |
| 3 | Browse | Tree connect, directory listing, metadata | 5-6 runs |
| 4 | Read/Write | File operations, streaming | 4-5 runs |
| 5 | Compatibility | Windows/macOS real client testing | 5-6 runs |
| 6 | Hardening | SMB 2.1, signing, credits, stability | 4-5 runs |

**Total: 25-31 agent runs across 6 phases.**

---

## 12. Phase 1 Sprint Tasks

Concrete task list for Phase 1 (TCP Skeleton + Dialect Negotiation).

### Setup

- [ ] Create `samba-dave/` directory structure
- [ ] Create `samba-dave.gemspec` with dependencies
- [ ] Create `Gemfile` referencing gemspec
- [ ] Create `spec/spec_helper.rb` with RSpec configuration
- [ ] Add `samba-dave` to root `Gemfile` as path dependency
- [ ] Confirm `bundle install` and `bundle exec rspec` work

### Constants + Header (BinData)

- [ ] Define `SambaDave::Protocol::Constants` — all SMB2 command codes, status codes, flags, NT status codes
- [ ] Define `SambaDave::Protocol::Header` as BinData::Record — 64-byte SMB2 sync header
- [ ] Write spec: pack header to binary, verify 64 bytes with correct protocol ID
- [ ] Write spec: unpack binary to header, verify field extraction
- [ ] Write spec: round-trip (pack → unpack → verify fields match)

### TCP Transport

- [ ] Define `SambaDave::Protocol::Transport` — NetBIOS framing: read/write with 4-byte length prefix
- [ ] Write spec: frame a message (prepend length header)
- [ ] Write spec: read a framed message (parse length, read exact bytes)
- [ ] Write spec: handle partial reads (TCP fragmentation)

### Negotiate Command

- [ ] Define `SambaDave::Protocol::Commands::NegotiateRequest` as BinData::Record
- [ ] Define `SambaDave::Protocol::Commands::NegotiateResponse` as BinData::Record
- [ ] Write spec: parse a negotiate request with multiple dialects
- [ ] Write spec: build a negotiate response with selected dialect 0x0202
- [ ] Write spec: negotiate response includes server GUID and security buffer offset

### SMB1 Negotiate Detection

- [ ] Detect SMB1 `COM_NEGOTIATE` by checking for `\xFFSMB` signature
- [ ] When SMB1 detected, check dialect strings for `"SMB 2.002"` or `"SMB 2.???"`
- [ ] If found, respond with SMB2 NEGOTIATE Response (dialect 0x02FF)
- [ ] Write spec: SMB1 negotiate with SMB2 dialect strings returns SMB2 response

### Connection Handler

- [ ] Define `SambaDave::Connection` — accepts socket, reads messages in loop
- [ ] Connection reads framed message → parses header → dispatches to command handler
- [ ] Connection handles NEGOTIATE → returns negotiate response
- [ ] Connection handles unknown commands → returns STATUS_NOT_IMPLEMENTED
- [ ] Write spec: connection processes negotiate and returns valid response

### TCP Server

- [ ] Define `SambaDave::Server` — accepts constructor args (filesystem, security, share_name, port)
- [ ] Server listens on TCP port, spawns thread per connection
- [ ] Server generates and stores server GUID
- [ ] `start` method blocks (runs accept loop)
- [ ] `start` method supports non-blocking mode for tests (accept in thread)
- [ ] `stop` method closes listener and all connections
- [ ] Write spec: server starts, accepts connection, handles negotiate, stops cleanly

### Exit Criteria

```bash
# Start the server
ruby -e "
  require 'samba_dave/server'
  require 'dave/file_system_provider'
  SambaDave::Server.new(
    filesystem: Dave::FileSystemProvider.new(root: '/tmp/smb-test'),
    share_name: 'test',
    port: 4450
  ).start
"

# In another terminal:
smbclient -L //localhost -p 4450 --option="client min protocol=SMB2"
# Should see negotiation attempt (will fail at auth — that's Phase 2)
```

---

## Appendix: Technology Choices

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Binary serialisation | BinData | Declarative, handles endianness, used by ruby_smb |
| NTLM messages | rubyntlm | MIT, handles Type 1/2/3, NTLMv2 support |
| SPNEGO/ASN.1 | Custom (~100 LOC) | Simpler than adding a full ASN.1 gem; SPNEGO subset is small |
| TCP server | Ruby TCPServer + Thread | Simple, stdlib-only; Async gem optional later |
| Hashing | OpenSSL (stdlib) | MD4, HMAC-MD5 for NTLMv2 |
| Threading | Thread-per-connection | Simple, sufficient for expected load |
| Port | 445 (prod) / 4450 (dev) | 445 needs root; high port for development |

## Appendix: File Information Structures

### FileBasicInformation (Class 0x04)

```
Offset  Size  Field
──────  ────  ─────
 0       8    CreationTime      (FILETIME)
 8       8    LastAccessTime    (FILETIME)
16       8    LastWriteTime     (FILETIME)
24       8    ChangeTime        (FILETIME)
32       4    FileAttributes    (uint32)
36       4    Reserved          (uint32)
```

### FileStandardInformation (Class 0x05)

```
Offset  Size  Field
──────  ────  ─────
 0       8    AllocationSize    (int64)
 8       8    EndOfFile         (int64)  — actual file size
16       4    NumberOfLinks     (uint32) — always 1
20       1    DeletePending     (uint8)
21       1    Directory         (uint8)
22       2    Reserved          (uint16)
```

### FileBothDirectoryInformation (Class 0x03)

Used for QUERY_DIRECTORY responses:

```
Offset  Size  Field
──────  ────  ─────
 0       4    NextEntryOffset   (uint32) — 0 for last entry
 4       4    FileIndex         (uint32)
 8       8    CreationTime      (FILETIME)
16       8    LastAccessTime    (FILETIME)
24       8    LastWriteTime     (FILETIME)
32       8    ChangeTime        (FILETIME)
40       8    EndOfFile         (int64)
48       8    AllocationSize    (int64)
56       4    FileAttributes    (uint32)
60       4    FileNameLength    (uint32) — bytes, not chars
64       4    EaSize            (uint32)
68       1    ShortNameLength   (uint8)
69       1    Reserved          (uint8)
70      24    ShortName         (24 bytes, UTF-16LE, 8.3 format)
94     var    FileName          (UTF-16LE, FileNameLength bytes)
```
