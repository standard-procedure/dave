# dave-security

Default YAML-based authentication and authorisation provider for the Dave WebDAV server.

## Responsibility

Implements the `Dave::SecurityProvider` interface using a YAML configuration file:
- HTTP Basic authentication
- bcrypt password hashing
- Path-based read/read-write access rules
- Optional anonymous access

## Usage

```ruby
require "dave/security_configuration"

security = Dave::SecurityConfiguration.new(config_path: "/etc/dave/security.yml")

# Use with Dave::Server
server = Dave::Server.new(
  filesystem: some_provider,
  security: security
)
```

## Configuration File

```yaml
# dave-security.yml
realm: "Dave WebDAV"
authentication: basic

users:
  alice:
    password: "$2a$12$..."  # bcrypt hash
    display_name: "Alice Smith"
    access:
      - path: "/"
        permission: read_write

  bob:
    password: "$2a$12$..."
    access:
      - path: "/"
        permission: read
      - path: "/bob/"
        permission: read_write

anonymous:
  enabled: false
  access:
    - path: "/public/"
      permission: read
```

### Generating Password Hashes

```ruby
require "bcrypt"
puts BCrypt::Password.create("my_password")
```

### Path Matching

- Paths are matched as prefixes with `/` boundaries
- More specific paths override less specific ones
- No match → access denied

## Custom Providers

To build your own security provider (e.g., LDAP, OAuth, database):

1. Implement all methods defined in the `Dave::SecurityProvider` interface
2. Include `Dave::SecurityProvider::ComplianceTests` in your RSpec suite
3. Pass your provider to `Dave::Server.new(security: your_provider)`

## Tests

```bash
bundle exec rspec
```
