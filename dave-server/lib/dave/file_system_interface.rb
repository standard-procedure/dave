module Dave
  module FileSystemInterface
    # Returns resource metadata. Returns nil if resource does not exist.
    # @param path [String] URL-decoded path e.g. "/documents/report.pdf"
    # @return [Dave::Resource, nil]
    def get_resource(path) = raise NotImplementedError

    # Lists direct children of a collection. Returns nil if path is not a collection.
    # @param path [String] URL-decoded collection path e.g. "/documents/"
    # @return [Array<Dave::Resource>, nil]
    def list_children(path) = raise NotImplementedError

    # Returns resource content as an IO-like object (responds to #read and #each).
    # @param path [String]
    # @return [IO]
    # @raise [Dave::NotFoundError] if resource does not exist
    def read_content(path) = raise NotImplementedError

    # Creates or overwrites a resource. Returns ETag of written resource.
    # @param path [String]
    # @param content [IO] readable stream
    # @param content_type [String, nil] MIME type hint from client
    # @return [String] ETag
    # @raise [Dave::NotFoundError] if parent collection does not exist
    def write_content(path, content, content_type: nil) = raise NotImplementedError

    # Creates a new collection at path.
    # @param path [String]
    # @raise [Dave::AlreadyExistsError] if path is already mapped
    # @raise [Dave::NotFoundError] if parent collection does not exist
    def create_collection(path) = raise NotImplementedError

    # Deletes a resource or collection (recursive for collections).
    # @param path [String]
    # @return [Array<String>] paths that could NOT be deleted (empty on full success)
    # @raise [Dave::NotFoundError] if path does not exist
    def delete(path) = raise NotImplementedError

    # Copies a resource or collection from src to dst.
    # @param src [String]
    # @param dst [String]
    # @param depth [Symbol] :zero or :infinity
    # @param overwrite [Boolean]
    # @return [Symbol] :created or :no_content
    # @raise [Dave::NotFoundError] if src does not exist or dst parent missing
    # @raise [Dave::AlreadyExistsError] if overwrite is false and dst exists
    def copy(src, dst, depth: :infinity, overwrite: true) = raise NotImplementedError

    # Moves a resource or collection from src to dst.
    # @param src [String]
    # @param dst [String]
    # @param overwrite [Boolean]
    # @return [Symbol] :created or :no_content
    # @raise [Dave::NotFoundError] if src does not exist or dst parent missing
    # @raise [Dave::AlreadyExistsError] if overwrite is false and dst exists
    def move(src, dst, overwrite: true) = raise NotImplementedError

    # Returns all dead properties for a resource.
    # @param path [String]
    # @return [Hash<String, String>] Clark-notation name ("{ns}local") => XML value string
    def get_properties(path) = raise NotImplementedError

    # Sets (merges) dead properties on a resource.
    # @param path [String]
    # @param properties [Hash<String, String>] Clark-notation name => XML value string
    # @raise [Dave::NotFoundError]
    def set_properties(path, properties) = raise NotImplementedError

    # Removes dead properties from a resource. Missing names are silently ignored.
    # @param path [String]
    # @param names [Array<String>] Clark-notation property names
    # @raise [Dave::NotFoundError]
    def delete_properties(path, names) = raise NotImplementedError

    # Creates a write lock on path. Returns the lock token.
    # Only called if supports_locking? returns true.
    # @param path [String]
    # @param scope [Symbol] :exclusive or :shared
    # @param depth [Symbol] :zero or :infinity
    # @param owner [String, nil] XML owner fragment (stored verbatim)
    # @param timeout [Integer, Symbol] seconds or :infinite
    # @return [String] lock token (UUID URN, e.g. "urn:uuid:...")
    # @raise [Dave::LockedError] if a conflicting lock exists
    def lock(path, scope:, depth:, owner: nil, timeout: 3600) = raise NotImplementedError

    # Removes the lock identified by token from path's scope.
    # @param path [String]
    # @param token [String] lock token URN
    # @raise [Dave::NotFoundError] if token not found or path not in lock scope
    def unlock(path, token) = raise NotImplementedError

    # Returns all active locks applying to path (direct and inherited depth-infinity locks).
    # @param path [String]
    # @return [Array<Dave::LockInfo>]
    def get_lock(path) = raise NotImplementedError

    # Returns true if this provider supports write locking.
    # @return [Boolean]
    def supports_locking? = raise NotImplementedError

    # Returns bytes available for new content at path, or nil if unknown.
    # @param path [String]
    # @return [Integer, nil]
    def quota_available_bytes(path) = raise NotImplementedError

    # Returns bytes currently used by stored content at path, or nil if unknown.
    # @param path [String]
    # @return [Integer, nil]
    def quota_used_bytes(path) = raise NotImplementedError
  end
end

require_relative "file_system_interface/compliance_tests"
