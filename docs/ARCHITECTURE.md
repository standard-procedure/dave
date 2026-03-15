# Dave — Architecture

> Overall architecture of the Dave multi-protocol document server platform.

---

## Overview

Dave is a **multi-protocol document server** implemented as a collection of Ruby gems. It provides both **WebDAV** (HTTP) and **SMB2** (native file sharing) access to the same underlying storage, using a shared pluggable provider architecture.

The key insight: one `FileSystemProvider` implementation serves both protocols. Write an adapter once (e.g., `C8OFileSystemProvider` for your Rails app), and users can access their files via WebDAV (browser, sync clients) or SMB (native OS file manager — Finder, Explorer).

```
┌────────────────────────────────────────────────────────────────┐
│                    Dave Platform                                │
│                                                                │
│  ┌──────────────────────┐        ┌──────────────────────┐      │
│  │    dave-server         │        │    samba-dave          │      │
│  │    (Rack/HTTP)         │        │    (TCP/SMB2)          │      │
│  │    WebDAV Protocol     │        │    SMB2 Protocol       │      │
│  │    Port 80/443         │        │    Port 445            │      │
│  │                        │        │                        │      │
│  │  ┌──────┐ ┌────────┐  │        │  ┌──────┐ ┌────────┐  │      │
│  │  │ XML  │ │ Method │  │        │  │Binary│ │Command │  │      │
│  │  │Parser│ │ Router │  │        │  │Parser│ │Dispatch│  │      │
│  │  └──────┘ └────────┘  │        │  └──────┘ └────────┘  │      │
│  └──────────┬─────────────┘        └──────────┬─────────────┘      │
│             │                                  │                   │
│             └──────────┬───────────────────────┘                   │
│                        │                                           │
│              ┌─────────▼──────────┐                                │
│              │  Shared Providers   │                                │
│              │                     │                                │
│              │  ┌──────────────┐   │                                │
│              │  │ FileSystem   │   │  ← Dave::FileSystemInterface   │
│              │  │ Provider     │   │    (one adapter, both protocols)│
│              │  └──────────────┘   │                                │
│              │  ┌──────────────┐   │                                │
│              │  │ Security     │   │  ← Dave::SecurityInterface     │
│              │  │ Provider     │   │                                │
│              │  └──────────────┘   │                                │
│              └─────────────────────┘                                │
└────────────────────────────────────────────────────────────────────┘
                         │
                         ▼
              ┌──────────────────┐
              │  Storage Backend  │
              │  (local disk, S3, │
              │   database, etc.) │
              └──────────────────┘
```

---

## Design Principles

### 1. Dependency Inversion
Both `Dave::Server` (WebDAV) and `SambaDave::Server` (SMB) depend on **interfaces**, not concrete implementations. FileSystem and Security providers are injected at construction time. This enables:
- Testing with in-memory fakes
- Custom backends (S3, database, etc.)
- Custom auth (OAuth, LDAP, app-specific passwords, etc.)
- **One provider, two protocols** — write once, serve via WebDAV and SMB

### 2. Single Responsibility
Each gem has one job:
- `dave-server` — HTTP/WebDAV protocol handling + shared interface definitions
- `dave-filesystem` — default local filesystem storage backend
- `dave-security` — default YAML-based authentication and authorisation
- `samba-dave` — SMB2 protocol handling (TCP server, binary wire format)

### 3. No Global State
All state is scoped to the server instance. Multiple server instances (even mixing WebDAV and SMB) with different configurations can coexist in the same process.

### 4. Thread Safety
Both servers may run in threaded environments. All shared state uses proper synchronisation:
- `Dave::Server` — lock manager uses mutex
- `SambaDave::Server` — thread-per-connection, shared open file tracking protected by mutex
- Providers must be thread-safe.

### 5. Streaming
Large files are streamed, not buffered in memory. The filesystem provider returns IO objects; both servers pass them directly to their transport layer.

### 6. Protocol Isolation
All protocol-specific knowledge is contained within each server gem:
- `dave-server` knows about XML, HTTP methods, WebDAV headers — but nothing about SMB
- `samba-dave` knows about binary wire format, NTLM, SMB2 commands — but nothing about HTTP
- Providers know nothing about either protocol

---

## Request Processing Pipeline

```
Incoming Rack Request
        │
        ▼
┌─────────────────┐
│ 1. Path Normalisation │  Strip prefix, ensure proper encoding
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 2. Authentication│  SecurityProvider.authenticate(request)
└────────┬────────┘  → 401 if required but not provided
         │
         ▼
┌─────────────────┐
│ 3. Authorisation │  SecurityProvider.authorised?(principal, path, op)
└────────┬────────┘  → 403 if not authorised
         │
         ▼
┌─────────────────┐
│ 4. Lock Check    │  For write ops: validate If header, check lock tokens
└────────┬────────┘  → 423 if locked and token not submitted
         │
         ▼
┌─────────────────┐
│ 5. Method Handler│  Dispatch to PROPFIND, PUT, GET, etc.
└────────┬────────┘  Each handler uses FileSystemProvider
         │
         ▼
┌─────────────────┐
│ 6. Response      │  Build Rack response [status, headers, body]
└─────────────────┘
```

**Order matters:** Auth → Conditional headers → Method processing (per RFC 4918 §8.1)

---

## Gem Boundaries

### dave-server

**Depends on:** Rack, Nokogiri

**Defines:**
- `Dave::Server` — the Rack application (WebDAV)
- `Dave::FileSystemInterface` — interface module (contract) — **shared with samba-dave**
- `Dave::SecurityInterface` — interface module (contract) — **shared with samba-dave**
- `Dave::Resource` — value object for file/collection metadata — **shared with samba-dave**
- `Dave::Principal` — authenticated user value object — **shared with samba-dave**
- `Dave::LockManager` — in-memory lock management
- `Dave::XmlRequest` — parses PROPFIND/PROPPATCH/LOCK request bodies
- `Dave::XmlResponse` — builds multistatus/propstat/lockdiscovery responses
- Method handlers: one class per WebDAV method
- Error classes: `Dave::Error`, `Dave::NotFoundError`, etc.
- `Dave::FileSystemInterface::ComplianceTests` — provider verification
- `Dave::SecurityInterface::ComplianceTests` — provider verification

**Does NOT contain:**
- Concrete filesystem implementation
- Concrete security implementation
- Framework-specific code
- Any SMB/binary protocol knowledge

### dave-filesystem

**Depends on:** dave-server (for interface/error definitions)

**Defines:**
- `Dave::FileSystemProvider` — local disk implementation
  - Maps WebDAV paths to filesystem paths under a root directory
  - Stores dead properties in sidecar `.dave-props/` directory (JSON files)
  - Computes live properties from filesystem metadata

**Design decision: Property storage**

Dead properties need persistent storage alongside files. Options considered:

| Approach | Pros | Cons |
|----------|------|------|
| **Sidecar directory** (`.dave-props/`) | Simple, portable, no external deps | Extra files, needs cleanup on delete |
| SQLite database | Fast queries, single file | External dependency, migration management |
| Extended attributes (xattr) | No extra files, native | OS-dependent, size limits, not all FS support |

**Choice: Sidecar directory.** Simplest, works everywhere, no external dependencies. JSON files named by SHA256 of the resource path.

### samba-dave

**Depends on:** dave-server (for interface definitions, Resource, Principal, errors), rubyntlm, bindata

**Defines:**
- `SambaDave::Server` — TCP server on port 445 (SMB2 protocol)
- `SambaDave::Connection` — per-connection state machine
- `SambaDave::Session` — authenticated session state
- `SambaDave::TreeConnect` — mounted share state
- `SambaDave::OpenFile` — file handle tracking (FileId → path + state)
- `SambaDave::Authenticator` — NTLM challenge-response using app-specific passwords
- `SambaDave::Protocol::Header` — SMB2 header (BinData)
- `SambaDave::Protocol::Transport` — TCP framing (4-byte NetBIOS prefix)
- `SambaDave::Protocol::Commands::*` — one handler per SMB2 command
- `SambaDave::NTLM::*` — SPNEGO wrapping, challenge generation/validation
- `SambaDave::ComplianceTests` — SMB-specific provider verification

**Does NOT contain:**
- Concrete filesystem implementation
- Concrete security implementation
- Any HTTP/WebDAV/XML knowledge
- Active Directory or Kerberos integration

### dave-security

**Depends on:** dave-server (for interface/error definitions), bcrypt

**Defines:**
- `Dave::SecurityConfiguration` — YAML-based auth/authz
  - Parses YAML config at startup
  - Verifies passwords with bcrypt
  - Matches paths using prefix rules
  - Supports HTTP Basic authentication

---

## Lock Manager Architecture

```
┌─────────────────────────────────┐
│         Dave::LockManager        │
│                                  │
│  @locks: Hash<token, LockInfo>   │
│  @mutex: Mutex                   │
│                                  │
│  • lock(path, scope, type,       │
│         depth, owner, timeout)   │
│    → token                       │
│                                  │
│  • unlock(token)                 │
│    → boolean                     │
│                                  │
│  • refresh(token, timeout)       │
│    → LockInfo                    │
│                                  │
│  • locks_for(path)               │
│    → Array<LockInfo>             │
│                                  │
│  • locked?(path)                 │
│    → boolean                     │
│                                  │
│  • conflicts?(path, scope)       │
│    → boolean                     │
│                                  │
│  • valid_token?(token, path)     │
│    → boolean                     │
│                                  │
│  • cleanup_expired!              │
│    → void                        │
└─────────────────────────────────┘
```

**LockInfo struct:**
```ruby
LockInfo = Struct.new(
  :token,       # String (UUID URN)
  :path,        # String (lock root)
  :scope,       # :exclusive | :shared
  :type,        # :write
  :depth,       # :zero | :infinity
  :owner,       # String (XML fragment)
  :timeout,     # Integer (seconds) or :infinite
  :principal,   # String (authenticated user)
  :created_at,  # Time
  keyword_init: true
)
```

**Lock resolution:** For any path, a lock applies if:
1. The lock root IS the path (direct lock), OR
2. The lock root is an ancestor of the path AND lock depth is infinity (indirect lock)

---

## XML Processing

### Namespaces

```ruby
DAV_NAMESPACE = "DAV:"
```

All WebDAV elements use the `DAV:` namespace. Dead properties may use arbitrary namespaces.

### Request Parsing

Uses Nokogiri to parse incoming XML. Defence against XXE:

```ruby
Nokogiri::XML(body) { |config|
  config.strict.nonet.noent  # No network, no entity expansion
}
```

### Response Building

Builder pattern for constructing XML responses:

```ruby
# Conceptual API
builder = Dave::XmlResponse::MultiStatus.new
builder.response("/path") do |r|
  r.propstat(status: 200) do |ps|
    ps.property("DAV:", "displayname", "My File")
    ps.property("DAV:", "getcontentlength", "1234")
  end
  r.propstat(status: 404) do |ps|
    ps.property("DAV:", "getcontentlanguage")
  end
end
builder.to_xml
```

---

## SMB Server Architecture (samba-dave)

### Connection Model

Unlike dave-server (which is a Rack middleware in someone else's HTTP server), samba-dave runs its own TCP server:

```
┌─────────────────────────────────────────────────────────┐
│                  SambaDave::Server                       │
│                                                         │
│  TCPServer (port 445)                                   │
│  @server_guid: 16 bytes                                 │
│  @filesystem: Dave::FileSystemInterface                 │
│  @security: Dave::SecurityInterface (optional)          │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Connection (Thread per client)                  │    │
│  │                                                  │    │
│  │  State: INITIAL → NEGOTIATED → AUTHENTICATED     │    │
│  │                → CONNECTED (tree connected)      │    │
│  │                                                  │    │
│  │  ┌───────────┐   ┌────────────┐                  │    │
│  │  │ Session   │   │ TreeConnect │                  │    │
│  │  │ (per user)│──▶│ (per share) │                  │    │
│  │  └───────────┘   └─────┬──────┘                  │    │
│  │                        │                          │    │
│  │                  ┌─────▼──────┐                   │    │
│  │                  │  OpenFile   │                   │    │
│  │                  │  (per file) │                   │    │
│  │                  │  FileId → path + state          │    │
│  │                  └────────────┘                   │    │
│  └──────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

### Authentication: App-Specific Passwords

samba-dave uses **app-generated credentials** rather than Active Directory:

1. Host application generates per-user SMB credentials (UUID username + random password)
2. User enters once when mounting; OS saves in keychain
3. NTLM is just the **wire format** — server validates using known plaintext password
4. No AD, no Kerberos, no domain controller

This is the same pattern as Gmail's "app passwords" for IMAP.

### SMB2 Request Processing

```
TCP Data Received
        │
        ▼
┌──────────────────┐
│ 1. Transport      │  Read 4-byte NetBIOS length prefix + message body
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 2. Header Parse   │  Unpack 64-byte SMB2 header (BinData)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 3. Session Check  │  Validate SessionId (except NEGOTIATE/SESSION_SETUP)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 4. Tree Check     │  Validate TreeId (for file operations)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 5. Command        │  Dispatch to handler based on Command code
│    Dispatch       │  Handler uses FileSystemProvider
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 6. Response       │  Build response header + payload, frame, send
└──────────────────┘
```

---

## Testing Strategy

### Unit Tests (per gem)
- Each class has its own spec file
- Mock providers for server tests
- Fast, isolated, no I/O

### Integration Tests

**dave-server (WebDAV):**
- Use Rack::Test to send HTTP requests
- Wire up real (or in-memory) providers
- Test full request/response cycle
- Verify XML responses with Nokogiri assertions

**samba-dave (SMB):**
- Use `smbclient` CLI for integration tests
- Binary packet fixtures captured from Wireshark
- Test full connection lifecycle (negotiate → auth → tree → ops → disconnect)

### Compliance Tests (provider gems)
- Shared example groups included by implementers
- `Dave::FileSystemInterface::ComplianceTests` — verifies WebDAV operations
- `SambaDave::ComplianceTests` — verifies SMB-relevant operations
- Test the contract, not the implementation
- Any passing provider works with **both** Dave::Server and SambaDave::Server

### End-to-End Tests
- **WebDAV:** litmus test suite, real client testing (Finder, Explorer, Cyberduck)
- **SMB:** smbclient CLI tests, mount from Windows Explorer, mount from macOS Finder

### Test Organisation

```
dave-server/
  spec/
    unit/
      server_spec.rb
      xml_request_spec.rb
      xml_response_spec.rb
      lock_manager_spec.rb
      handlers/
        propfind_handler_spec.rb
        put_handler_spec.rb
        ...
    integration/
      propfind_spec.rb
      proppatch_spec.rb
      get_put_spec.rb
      delete_spec.rb
      copy_move_spec.rb
      lock_unlock_spec.rb
      options_spec.rb
    spec_helper.rb

dave-filesystem/
  spec/
    unit/
      file_system_provider_spec.rb
    compliance/
      provider_compliance_spec.rb
    spec_helper.rb

dave-security/
  spec/
    unit/
      security_configuration_spec.rb
    compliance/
      provider_compliance_spec.rb
    spec_helper.rb

samba-dave/
  spec/
    samba_dave/
      server_spec.rb
      connection_spec.rb
      authenticator_spec.rb
      protocol/
        header_spec.rb
        transport_spec.rb
        commands/
          negotiate_spec.rb
          session_setup_spec.rb
          create_spec.rb
          read_spec.rb
          write_spec.rb
          query_info_spec.rb
          query_directory_spec.rb
    integration/
      mount_spec.rb
      file_operations_spec.rb
    spec_helper.rb
```
