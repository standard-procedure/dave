# frozen_string_literal: true

module SambaDave
  # Abstract security provider interface for SMB2 authentication.
  #
  # SMB2 uses NTLM challenge-response, which requires the server to know the
  # user's plaintext password to validate the NTLMv2 response. This interface
  # provides two methods:
  #
  #   1. `credential_for(username)` — returns the plaintext password for the
  #      given username, or nil if the user is unknown.
  #
  #   2. `authenticate(username, password)` — validates credentials and returns
  #      a user identity object (any truthy value), or nil if invalid.
  #
  # ## App-Specific Password Pattern
  #
  # samba-dave is designed for the app-specific password pattern: the host
  # application (e.g. Rails) generates a random password per user and stores it.
  # The user enters it once when mounting the share; the OS saves it in the
  # system keychain.
  #
  # This means we hold plaintext passwords on the server side, which is what
  # allows NTLMv2 validation without Active Directory or domain controllers.
  #
  class SecurityProvider
    # Return the plaintext credential for the given username.
    #
    # @param username [String] the username (decoded from NTLM Type3 message)
    # @return [String, nil] the plaintext password, or nil if user not found
    def credential_for(username)
      raise NotImplementedError, "#{self.class}#credential_for not implemented"
    end

    # Authenticate with username and password.
    #
    # Called after NTLMv2 validation succeeds, to retrieve the user identity.
    #
    # @param username [String]
    # @param password [String] the plaintext password (same as credential_for returns)
    # @return [Object, nil] user identity (any truthy object) or nil if invalid
    def authenticate(username, password)
      raise NotImplementedError, "#{self.class}#authenticate not implemented"
    end
  end

  # Test security provider with a hardcoded username→password hash.
  #
  # Used in specs and development. NOT for production use.
  #
  # @example
  #   provider = TestSecurityProvider.new("alice" => "s3cr3t", "bob" => "hunter2")
  #   provider.credential_for("alice")     # => "s3cr3t"
  #   provider.authenticate("alice", "s3cr3t")  # => { username: "alice" }
  #   provider.authenticate("alice", "wrong")   # => nil
  #
  class TestSecurityProvider < SecurityProvider
    # @param users [Hash<String, String>] username → plaintext password
    def initialize(users = {})
      @users = users
    end

    # @return [String, nil] plaintext password or nil if user unknown
    def credential_for(username)
      @users[username]
    end

    # @return [Hash, nil] minimal identity hash or nil if credentials invalid
    def authenticate(username, password)
      return nil unless @users[username] == password

      { username: username }
    end
  end
end
