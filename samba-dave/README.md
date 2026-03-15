# samba-dave

An SMB2 file server that shares the Dave pluggable provider architecture with [dave-server](../dave-server) (WebDAV).

**One provider, two protocols.** Write a `FileSystemProvider` once, and users can access their files via WebDAV (browsers, sync clients) or SMB (native OS file managers — Finder, Explorer).

## Status

🔲 **In Development** — see [SAMBA-DAVE-IMPLEMENTATION-PLAN.md](../docs/SAMBA-DAVE-IMPLEMENTATION-PLAN.md) for the phase plan.

## Quick Start

```ruby
require "samba_dave/server"
require "dave/file_system_provider"

server = SambaDave::Server.new(
  filesystem: Dave::FileSystemProvider.new(root: "/var/shares"),
  share_name: "files",
  port: 445
)

server.start
```

### With Authentication (App-Specific Passwords)

```ruby
server = SambaDave::Server.new(
  filesystem: MyFileSystemProvider.new,
  security: MySecurityProvider.new,
  share_name: "documents",
  port: 445
)

server.start
```

The security provider authenticates using app-generated credentials (UUID username + random password). No Active Directory or Kerberos required. NTLM is used as the wire format only.

## Architecture

See [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) for the multi-protocol architecture and [docs/SMB-SPEC.md](../docs/SMB-SPEC.md) for the SMB2 protocol reference.

## Shared Interfaces

samba-dave uses the same interfaces as dave-server:

- `Dave::FileSystemInterface` — file and directory operations
- `Dave::SecurityInterface` — authentication and authorisation
- `Dave::Resource` — file/collection metadata value object
- `Dave::Principal` — authenticated user identity

## Testing

```bash
cd samba-dave
bundle install
bundle exec rspec
```

### Integration Testing

```bash
# Start a test server
ruby -e "require 'samba_dave/server'; SambaDave::Server.new(filesystem: ..., port: 4450).start"

# Connect with smbclient
smbclient //localhost:4450/files -U testuser%testpass

# Mount from macOS
open smb://localhost:4450/files
```

## License

MIT
