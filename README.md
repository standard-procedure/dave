# Dave

A **multi-protocol document server** platform implemented as a Ruby gem mono-repo.

Dave provides both **WebDAV** (HTTP) and **SMB2** (native file sharing) access to the same underlying storage, using shared pluggable provider interfaces. Write one `FileSystemProvider` adapter, and users can access their files via WebDAV (browsers, sync clients) or SMB (native OS file managers — Finder, Explorer).

## Features

- **Two protocols, one provider** — WebDAV and SMB2 share the same `FileSystemInterface`
- **RFC 4918 compliant WebDAV** — full WebDAV specification
- **SMB2 native file sharing** — mount as a network drive on Windows and macOS
- **Embeddable** — mount WebDAV in Rails, Hanami, or any Rack app; run SMB as a standalone TCP server
- **Pluggable storage** — default local filesystem, or bring your own (S3, database, etc.)
- **Pluggable auth** — default YAML config with bcrypt, or bring your own (LDAP, OAuth, app passwords, etc.)
- **Locking support** — WebDAV write locks; SMB sharing semantics
- **Thread-safe** — designed for concurrent environments

## Quick Start

### WebDAV (config.ru)

```ruby
# Gemfile
gem "dave-server"
gem "dave-filesystem"
gem "dave-security"   # optional

# config.ru
require "dave/server"
require "dave/file_system_provider"

run Dave::Server.new(
  filesystem: Dave::FileSystemProvider.new(root: "/var/shares")
)
```

### SMB (standalone)

```ruby
# Gemfile
gem "samba-dave"
gem "dave-filesystem"

# smb_server.rb
require "samba_dave/server"
require "dave/file_system_provider"

SambaDave::Server.new(
  filesystem: Dave::FileSystemProvider.new(root: "/var/shares"),
  share_name: "files",
  port: 445
).start
```

### Rails (both protocols)

```ruby
# config/routes.rb — WebDAV
mount Dave::Server.new(
  filesystem: C8OFileSystemProvider.new,
  security: C8OSecurityProvider.new
) => "/dav"

# config/initializers/smb.rb — SMB
Thread.new do
  SambaDave::Server.new(
    filesystem: C8OFileSystemProvider.new,
    security: C8OSmBSecurityProvider.new,
    share_name: "documents",
    port: 445
  ).start
end
```

## Gems

| Gem | Description |
|-----|-------------|
| `dave-server` | WebDAV Rack application + shared interface definitions |
| `dave-filesystem` | Default local filesystem provider |
| `dave-security` | Default YAML-based authentication & authorisation |
| `samba-dave` | SMB2 TCP server for native file sharing |

## Custom Providers

Dave uses a pluggable provider architecture. Implement the interface once, and it works for both WebDAV and SMB:

```ruby
# Works for both protocols!
my_provider = MyS3Provider.new(bucket: "my-files")

# WebDAV
Dave::Server.new(filesystem: my_provider)

# SMB
SambaDave::Server.new(filesystem: my_provider, share_name: "files")
```

Each provider interface includes a compliance test suite you can use to verify your implementation works with both protocols.

## Development

- [docs/IMPLEMENTATION-PLAN.md](docs/IMPLEMENTATION-PLAN.md) — WebDAV development plan
- [docs/SAMBA-DAVE-IMPLEMENTATION-PLAN.md](docs/SAMBA-DAVE-IMPLEMENTATION-PLAN.md) — SMB development plan
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — multi-protocol architecture
- [docs/SMB-SPEC.md](docs/SMB-SPEC.md) — SMB2 protocol reference

## License

MIT
