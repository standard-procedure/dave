# dave-server

Core Rack application for the Dave WebDAV server.

## Responsibility

`dave-server` handles all WebDAV protocol concerns:
- Parsing HTTP requests and WebDAV-specific headers (Depth, Destination, If, Lock-Token, Overwrite, Timeout)
- Parsing XML request bodies (PROPFIND, PROPPATCH, LOCK)
- Routing to the appropriate method handler
- Enforcing authentication and authorisation via the SecurityProvider interface
- Managing locks via the built-in LockManager
- Building XML response bodies (Multi-Status, lockdiscovery, etc.)
- Returning correct HTTP status codes per RFC 4918

## Usage

```ruby
require "dave/server"

app = Dave::Server.new(
  filesystem: some_filesystem_provider,
  security: some_security_provider,     # optional
  prefix: "/dav",                       # optional URL prefix
  compliance_class: 2                   # 1 = no locking, 2 = with locking
)

# Use as Rack app
run app
```

## Key Classes

| Class | Purpose |
|-------|---------|
| `Dave::Server` | Rack app entry point (`#call(env)`) |
| `Dave::LockManager` | In-memory lock management with mutex |
| `Dave::XmlRequest` | Parses PROPFIND/PROPPATCH/LOCK XML bodies |
| `Dave::XmlResponse` | Builds Multi-Status and other XML responses |
| `Dave::Principal` | Value object for authenticated users |

## Provider Interfaces

This gem defines the interfaces that providers must implement:

- `Dave::FileSystemProvider` — storage operations (see `docs/IMPLEMENTATION-PLAN.md`)
- `Dave::SecurityProvider` — auth/authz operations

## Tests

```bash
bundle exec rspec
```
