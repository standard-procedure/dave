module Dave
  module SecurityInterface
    # Authenticates a request. Returns an authenticated Principal or nil.
    # @param request [Rack::Request]
    # @return [Dave::Principal, nil]
    def authenticate(request) = raise NotImplementedError

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
