# dave-filesystem

Default local filesystem provider for the Dave WebDAV server.

## Responsibility

Implements the `Dave::FileSystemProvider` interface using the local filesystem:
- Maps WebDAV paths to filesystem paths under a configurable root directory
- Provides file read/write/delete/copy/move operations
- Manages dead property storage in sidecar `.dave-props/` directory
- Computes live properties from filesystem metadata (size, timestamps, etc.)

## Usage

```ruby
require "dave/file_system_provider"

provider = Dave::FileSystemProvider.new(root: "/var/webdav")

# Use with Dave::Server
server = Dave::Server.new(filesystem: provider)
```

## Configuration

| Option | Type | Description |
|--------|------|-------------|
| `root` | String/Pathname | Root directory for file storage (must exist, must be writable) |

## Custom Providers

To build your own filesystem provider (e.g., S3, database):

1. Implement all methods defined in the `Dave::FileSystemProvider` interface
2. Include `Dave::FileSystemProvider::ComplianceTests` in your RSpec suite
3. Pass your provider to `Dave::Server.new(filesystem: your_provider)`

```ruby
RSpec.describe MyCustomProvider do
  include Dave::FileSystemProvider::ComplianceTests

  let(:provider) { MyCustomProvider.new(root: Dir.mktmpdir) }
end
```

## Tests

```bash
bundle exec rspec
```
