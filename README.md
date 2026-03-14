# Dave

A WebDAV server implemented as a Ruby/Rack gem.

Dave provides a complete, spec-compliant WebDAV implementation that can be mounted in any Rack-compatible application — Rails, Hanami, Sinatra, or standalone.

## Features

- **RFC 4918 compliant** — implements the full WebDAV specification
- **Embeddable** — mount in Rails, Hanami, or any Rack app
- **Pluggable storage** — default local filesystem, or bring your own (S3, database, etc.)
- **Pluggable auth** — default YAML config with bcrypt, or bring your own (LDAP, OAuth, etc.)
- **Locking support** — exclusive and shared write locks
- **Thread-safe** — designed for concurrent environments

## Quick Start

```ruby
# Gemfile
gem "dave-server"
gem "dave-filesystem"
gem "dave-security"   # optional
```

### Standalone (config.ru)

```ruby
require "dave/server"
require "dave/file_system_provider"

run Dave::Server.new(
  filesystem: Dave::FileSystemProvider.new(root: "/var/webdav")
)
```

### Rails

```ruby
# config/routes.rb
mount Dave::Server.new(
  filesystem: Dave::FileSystemProvider.new(root: Rails.root.join("storage/webdav")),
  security: Dave::SecurityConfiguration.new(config_path: Rails.root.join("config/dave-security.yml"))
) => "/dav"
```

## Gems

| Gem | Description |
|-----|-------------|
| `dave-server` | Core Rack application — WebDAV protocol handling |
| `dave-filesystem` | Default local filesystem provider |
| `dave-security` | Default YAML-based authentication & authorisation |

## Custom Providers

Dave uses a pluggable provider architecture. Implement the interface and pass it in:

```ruby
Dave::Server.new(
  filesystem: MyS3Provider.new(bucket: "my-webdav"),
  security: MyLDAPAuth.new(host: "ldap.example.com")
)
```

Each provider interface includes a compliance test suite you can use to verify your implementation.

## Development

See [docs/IMPLEMENTATION-PLAN.md](docs/IMPLEMENTATION-PLAN.md) for the full development plan.

## License

MIT
