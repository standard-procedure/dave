require "spec_helper"


RSpec.describe Dave::SecurityConfiguration do
  # Shared YAML config used across all tests.
  #
  # alice: read_write on /docs/ only
  # bob:   read on /public/ only
  # Neither user has access to /secret/
  let(:config_yaml) do
    <<~YAML
      realm: "Test WebDAV"
      users:
        alice:
          password: "$2a$12$IcHv0OoKirO8q.QlW/TwhuxdgGNoA7vAUyfQEtGjpCKWFeXsQaWWC"
          display_name: "Alice Smith"
          access:
            - path: "/docs/"
              permission: read_write
        bob:
          password: "$2a$12$5zfWFPno0jwx0y4Ea/VPzueT70gew5XBxSAoVCtOa.3BBjUq513dy"
          display_name: "Bob Jones"
          access:
            - path: "/public/"
              permission: read
            - path: "/bob/"
              permission: read_write
    YAML
  end

  subject { Dave::SecurityConfiguration.new(config_yaml) }

  # --- Unit tests ---

  describe "#initialize" do
    it "accepts a YAML string" do
      expect { Dave::SecurityConfiguration.new(config_yaml) }.not_to raise_error
    end

    it "accepts a file path" do
      require "tempfile"
      f = Tempfile.new(["config", ".yml"])
      f.write(config_yaml)
      f.close
      expect { Dave::SecurityConfiguration.new(f.path) }.not_to raise_error
      f.unlink
    end
  end

  describe "#authenticate" do
    it "returns a Principal with correct display_name" do
      principal = subject.authenticate(username: "alice", password: "alice_password")
      expect(principal.display_name).to eq("Alice Smith")
    end

    it "returns a Principal with id matching username" do
      principal = subject.authenticate(username: "bob", password: "bob_password")
      expect(principal.id).to eq("bob")
    end

    it "returns nil for wrong password" do
      expect(subject.authenticate(username: "alice", password: "wrong")).to be_nil
    end

    it "returns nil for unknown user" do
      expect(subject.authenticate(username: "charlie", password: "anything")).to be_nil
    end

    it "accepts string-keyed credentials" do
      principal = subject.authenticate("username" => "alice", "password" => "alice_password")
      expect(principal).not_to be_nil
      expect(principal.id).to eq("alice")
    end

    it "returns nil for string-keyed wrong password" do
      expect(subject.authenticate("username" => "alice", "password" => "wrong")).to be_nil
    end
  end

  describe "#challenge" do
    it "includes the configured realm" do
      expect(subject.challenge).to include("Test WebDAV")
    end

    it "is formatted as a Basic auth challenge" do
      expect(subject.challenge).to eq('Basic realm="Test WebDAV"')
    end
  end

  describe "#authorize" do
    let(:alice) { subject.authenticate(username: "alice", password: "alice_password") }
    let(:bob)   { subject.authenticate(username: "bob",   password: "bob_password") }

    context "alice (read_write on /docs/)" do
      it "can read files under /docs/" do
        expect(subject.authorize(alice, "/docs/report.txt", :read)).to be true
      end

      it "can write files under /docs/" do
        expect(subject.authorize(alice, "/docs/report.txt", :write)).to be true
      end

      it "cannot access files outside /docs/" do
        expect(subject.authorize(alice, "/secret/file.txt", :read)).to be false
      end
    end

    context "bob (read on /public/, read_write on /bob/)" do
      it "can read files under /public/" do
        expect(subject.authorize(bob, "/public/index.html", :read)).to be true
      end

      it "cannot write files under /public/" do
        expect(subject.authorize(bob, "/public/index.html", :write)).to be false
      end

      it "can read files under /bob/" do
        expect(subject.authorize(bob, "/bob/notes.txt", :read)).to be true
      end

      it "can write files under /bob/" do
        expect(subject.authorize(bob, "/bob/notes.txt", :write)).to be true
      end
    end

    context "more specific path overrides less specific" do
      # Use a config where bob has read on /bob/ and read_write on /bob/special/
      let(:layered_config_yaml) do
        <<~YAML
          realm: "Test"
          users:
            carol:
              password: "$2a$12$5zfWFPno0jwx0y4Ea/VPzueT70gew5XBxSAoVCtOa.3BBjUq513dy"
              display_name: "Carol"
              access:
                - path: "/shared/"
                  permission: read
                - path: "/shared/editable/"
                  permission: read_write
        YAML
      end
      let(:layered_provider) { Dave::SecurityConfiguration.new(layered_config_yaml) }
      let(:carol) { layered_provider.authenticate(username: "carol", password: "bob_password") }

      it "more specific read_write overrides less specific read for write" do
        expect(layered_provider.authorize(carol, "/shared/editable/doc.txt", :write)).to be true
      end

      it "less specific read still applies for read-only paths" do
        expect(layered_provider.authorize(carol, "/shared/readonly.txt", :read)).to be true
      end

      it "less specific read denies write on read-only paths" do
        expect(layered_provider.authorize(carol, "/shared/readonly.txt", :write)).to be false
      end
    end

    context "nil principal" do
      it "denies read" do
        expect(subject.authorize(nil, "/docs/", :read)).to be false
      end

      it "denies write" do
        expect(subject.authorize(nil, "/docs/", :write)).to be false
      end
    end

    context "no matching ACL entry" do
      let(:restricted_config_yaml) do
        <<~YAML
          realm: "Test"
          users:
            charlie:
              password: "$2a$12$IcHv0OoKirO8q.QlW/TwhuxdgGNoA7vAUyfQEtGjpCKWFeXsQaWWC"
              display_name: "Charlie"
              access:
                - path: "/charlie/"
                  permission: read_write
        YAML
      end
      let(:restricted_provider) { Dave::SecurityConfiguration.new(restricted_config_yaml) }
      let(:charlie) { restricted_provider.authenticate(username: "charlie", password: "alice_password") }

      it "denies access to paths not in ACL" do
        expect(restricted_provider.authorize(charlie, "/other/file.txt", :read)).to be false
      end
    end
  end

  describe "with root access user" do
    let(:root_config_yaml) do
      <<~YAML
        realm: "Root Test"
        users:
          admin:
            password: "$2a$12$IcHv0OoKirO8q.QlW/TwhuxdgGNoA7vAUyfQEtGjpCKWFeXsQaWWC"
            display_name: "Admin"
            access:
              - path: "/"
                permission: read_write
      YAML
    end
    let(:root_provider) { Dave::SecurityConfiguration.new(root_config_yaml) }
    let(:admin) { root_provider.authenticate(username: "admin", password: "alice_password") }

    it "admin can read any path" do
      expect(root_provider.authorize(admin, "/anything/file.txt", :read)).to be true
    end

    it "admin can write any path" do
      expect(root_provider.authorize(admin, "/anything/file.txt", :write)).to be true
    end
  end
end
