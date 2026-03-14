# Dave — Architecture

> Overall architecture of the Dave WebDAV mono-repo.

---

## Overview

Dave is a WebDAV server implemented as a collection of Ruby gems, designed to be embedded in any Rack-compatible application.

```
┌──────────────────────────────────────────────────┐
│                  Rack Application                 │
│                  (Rails, Hanami, etc.)            │
└──────────────────────┬───────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────┐
│                  Dave::Server                     │
│                  (Rack middleware / app)          │
│                                                  │
│  ┌─────────┐  ┌──────────┐  ┌─────────────────┐ │
│  │ Request  │  │  Method  │  │   Response      │ │
│  │ Parser   │──│  Router  │──│   Builder       │ │
│  │ (XML)    │  │          │  │   (XML)         │ │
│  └─────────┘  └────┬─────┘  └─────────────────┘ │
│                    │                              │
│         ┌──────────┼──────────┐                   │
│         ▼          ▼          ▼                   │
│  ┌────────┐  ┌──────────┐  ┌────────┐           │
│  │Security│  │FileSystem│  │  Lock  │           │
│  │Provider│  │ Provider │  │Manager │           │
│  └────────┘  └──────────┘  └────────┘           │
└──────────────────────────────────────────────────┘
         │           │
         ▼           ▼
   ┌──────────┐  ┌──────────────┐
   │YAML/Auth │  │  Local Disk  │
   │  Config  │  │  (or custom) │
   └──────────┘  └──────────────┘
```

---

## Design Principles

### 1. Dependency Inversion
Dave::Server depends on **interfaces**, not concrete implementations. FileSystem and Security providers are injected at construction time. This enables:
- Testing with in-memory fakes
- Custom backends (S3, database, etc.)
- Custom auth (OAuth, LDAP, etc.)

### 2. Single Responsibility
Each gem has one job:
- `dave-server` — HTTP/WebDAV protocol handling
- `dave-filesystem` — storage abstraction
- `dave-security` — authentication and authorisation

### 3. No Global State
All state is scoped to the `Dave::Server` instance. Multiple server instances with different configurations can coexist in the same process.

### 4. Thread Safety
The server may be used in threaded environments (Puma, etc.). All shared state (lock manager) uses proper synchronisation. Providers must be thread-safe.

### 5. Streaming
Large files are streamed, not buffered in memory. The filesystem provider returns IO objects; the server passes them directly to Rack.

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
- `Dave::Server` — the Rack application
- `Dave::FileSystemProvider` — interface module (contract)
- `Dave::SecurityProvider` — interface module (contract)
- `Dave::LockManager` — in-memory lock management
- `Dave::XmlRequest` — parses PROPFIND/PROPPATCH/LOCK request bodies
- `Dave::XmlResponse` — builds multistatus/propstat/lockdiscovery responses
- `Dave::Principal` — authenticated user value object
- Method handlers: one class per WebDAV method
- Error classes: `Dave::Error`, `Dave::NotFoundError`, etc.
- Compliance test modules for providers

**Does NOT contain:**
- Concrete filesystem implementation
- Concrete security implementation
- Framework-specific code

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

## Testing Strategy

### Unit Tests (per gem)
- Each class has its own spec file
- Mock providers for server tests
- Fast, isolated, no I/O

### Integration Tests (dave-server)
- Use Rack::Test to send HTTP requests
- Wire up real (or in-memory) providers
- Test full request/response cycle
- Verify XML responses with Nokogiri assertions

### Compliance Tests (provider gems)
- Shared example groups included by implementers
- Test the contract, not the implementation
- Any passing provider works with Dave::Server

### End-to-End Tests (Phase 6)
- litmus test suite (external WebDAV test tool)
- Real client testing (Finder, Explorer, Cyberduck)
- curl-based smoke tests

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
```
