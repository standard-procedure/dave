require_relative "security_interface/compliance_tests"

module Dave
  module SecurityInterface
    # Authenticates credentials. Returns an authenticated Principal or nil.
    # @param credentials [Hash] with :username and :password keys
    # @return [Dave::Principal, nil]
    def authenticate(credentials) = raise NotImplementedError

    # Returns the WWW-Authenticate challenge string.
    # @return [String] e.g. 'Basic realm="WebDAV"'
    def challenge = raise NotImplementedError

    # Returns true if principal may perform operation on path.
    # @param principal [Dave::Principal, nil]
    # @param path [String]
    # @param operation [Symbol] :read or :write
    # @return [Boolean]
    def authorize(principal, path, operation) = raise NotImplementedError
  end
end
