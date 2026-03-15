require "spec_helper"
require "dave/security_interface"

# Compliance spec: verifies that Dave::SecurityConfiguration satisfies the full
# SecurityInterface::ComplianceTests contract.
#
# Users in this config:
#   alice — read_write on /docs/ (valid_credentials / read_write_path)
#   bob   — read on /shared/ only (read_only_credentials / read_only_path)
#   /private/ — no ACL entry for either user (restricted_path)
RSpec.describe "Dave::SecurityConfiguration compliance" do
  # Pre-computed bcrypt hashes to avoid slow key-derivation in tests.
  # alice_password → $2a$12$IcHv0OoKirO8q.QlW/TwhuxdgGNoA7vAUyfQEtGjpCKWFeXsQaWWC
  # bob_password   → $2a$12$5zfWFPno0jwx0y4Ea/VPzueT70gew5XBxSAoVCtOa.3BBjUq513dy
  let(:config_yaml) do
    <<~YAML
      realm: "Compliance Test"
      users:
        alice:
          password: "$2a$12$IcHv0OoKirO8q.QlW/TwhuxdgGNoA7vAUyfQEtGjpCKWFeXsQaWWC"
          display_name: "Alice"
          access:
            - path: "/docs/"
              permission: read_write
        bob:
          password: "$2a$12$5zfWFPno0jwx0y4Ea/VPzueT70gew5XBxSAoVCtOa.3BBjUq513dy"
          display_name: "Bob"
          access:
            - path: "/shared/"
              permission: read
    YAML
  end

  subject { Dave::SecurityConfiguration.new(config_yaml) }

  let(:valid_credentials)     { { username: "alice", password: "alice_password" } }
  let(:read_only_credentials) { { username: "bob",   password: "bob_password" } }
  let(:invalid_credentials)   { { username: "alice", password: "wrong_password" } }

  let(:read_write_path) { "/docs/report.txt" }  # alice has read_write on /docs/
  let(:read_only_path)  { "/shared/index.html" } # bob has read on /shared/ only
  let(:restricted_path) { "/private/data.txt" }  # neither alice nor bob has any ACL entry

  include Dave::SecurityInterface::ComplianceTests
end
