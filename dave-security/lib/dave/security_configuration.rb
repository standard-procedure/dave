require "bcrypt"
require "yaml"
require "dave/principal"
require "dave/security_interface"

module Dave
  # Dave::SecurityConfiguration is the default authentication and authorisation
  # provider for the Dave WebDAV server.
  #
  # It reads a YAML configuration file (or YAML string) that defines users,
  # their bcrypt-hashed passwords, display names, and path-based ACL entries.
  #
  # Example config:
  #
  #   realm: "Dave WebDAV"
  #   users:
  #     alice:
  #       password: "$2a$12$..."
  #       display_name: "Alice Smith"
  #       access:
  #         - path: "/"
  #           permission: read_write
  #
  class SecurityConfiguration
    include Dave::SecurityInterface
    VERSION = "0.1.0"

    # @param source [String] either a file path (if the file exists) or raw YAML
    def initialize(source)
      yaml_string = if File.exist?(source.to_s)
                      File.read(source)
                    else
                      source
                    end
      @config = YAML.safe_load(yaml_string, symbolize_names: false)
    end

    # Authenticates a credentials hash.
    #
    # @param credentials [Hash] with String or Symbol keys :username / :password
    # @return [Dave::Principal, nil]
    def authenticate(credentials)
      username = credentials[:username] || credentials["username"]
      password = credentials[:password] || credentials["password"]

      return nil if username.nil? || password.nil?

      user_config = users[username.to_s]
      return nil unless user_config

      stored_hash = user_config["password"]
      return nil unless stored_hash

      begin
        bcrypt = BCrypt::Password.new(stored_hash)
        return nil unless bcrypt.is_password?(password)
      rescue BCrypt::Errors::InvalidHash
        return nil
      end

      Dave::Principal.new(
        id: username.to_s,
        display_name: user_config["display_name"] || username.to_s
      )
    end

    # Returns the WWW-Authenticate challenge string.
    #
    # @return [String] e.g. 'Basic realm="Dave WebDAV"'
    def challenge
      %(Basic realm="#{realm}")
    end

    # Returns true if the principal is permitted to perform the operation on path.
    #
    # ACL matching uses prefix matching. The most specific (longest) matching
    # path entry wins. If no entry matches, access is denied.
    #
    # @param principal [Dave::Principal, nil]
    # @param path [String]
    # @param operation [Symbol] :read or :write
    # @return [Boolean]
    def authorize(principal, path, operation)
      return false if principal.nil?

      user_config = users[principal.id.to_s]
      return false unless user_config

      access_list = user_config["access"] || []

      # Find all matching ACL entries (prefix match), pick most specific
      matching = access_list.select { |entry| path_matches?(path, entry["path"]) }
      return false if matching.empty?

      # Most specific = longest path prefix
      best = matching.max_by { |entry| entry["path"].length }
      permission_allows?(best["permission"], operation)
    end

    private

    def realm
      @config["realm"] || "WebDAV"
    end

    def users
      @config["users"] || {}
    end

    # Returns true if the request path falls under the ACL entry path.
    def path_matches?(request_path, acl_path)
      req = request_path.to_s
      acl = acl_path.to_s

      if acl.end_with?("/")
        # Collection prefix — request path must start with acl path
        req.start_with?(acl) || req == acl.chomp("/")
      else
        # Exact file match or prefix
        req == acl || req.start_with?("#{acl}/")
      end
    end

    def permission_allows?(permission, operation)
      case permission.to_s
      when "read_write"
        true
      when "read"
        operation == :read
      else
        false
      end
    end
  end
end
