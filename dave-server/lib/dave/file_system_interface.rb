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

    # Returns resource content as an IO-like object.
    #
    # The returned IO MUST be seekable — it has to respond to #seek and to
    # #read(length) — so consumers (e.g. the SMB READ command) can serve a
    # byte range without buffering the whole object. The reference provider
    # returns a File, which satisfies this. A remote-backed provider whose
    # underlying stream is not seekable should wrap it in an adapter that
    # translates #seek + #read(length) into ranged reads (e.g. HTTP Range
    # GETs) rather than returning a forward-only stream.
    #
    # @param path [String]
    # @return [IO] a seekable IO (responds to #read, #each and #seek)
    # @raise [Dave::NotFoundError] if resource does not exist
    def read_content(path) = raise NotImplementedError

    # Creates/overwrites a resource, or writes a partial range when `offset`
    # is given.
    #
    # With `offset: nil` (the default) this is a whole-file create/replace and
    # returns the new content's ETag.
    #
    # With an integer `offset` this is a partial write: `io`'s bytes are
    # spliced in starting at `offset`, extending the file (zero-filling any
    # gap) if it lands past the current end; bytes before the offset are left
    # untouched. Partial writes are only attempted against providers that
    # advertise #supports_partial_writes? — a provider that returns false
    # never receives a non-nil offset, so whole-file remains the universal
    # fallback and existing providers stay compliant unchanged. A partial
    # write need not return an ETag (computing a whole-file digest would
    # defeat the point) and may return nil.
    #
    # @param path [String]
    # @param io [IO] readable stream
    # @param offset [Integer, nil] byte offset to splice at; nil = whole file
    # @param content_type [String, nil] MIME hint (whole-file writes only)
    # @return [String, nil] ETag for a whole-file write; nil permitted for a partial write
    # @raise [Dave::NotFoundError] if parent collection does not exist
    def write_content(path, io, offset: nil, content_type: nil) = raise NotImplementedError

    # Resizes the resource at `path` to exactly `size` bytes: truncating drops
    # the tail, growing zero-fills. Only called against providers that
    # advertise #supports_partial_writes?; lets an EOF change touch only the
    # file length instead of re-transferring the whole object.
    #
    # @param path [String]
    # @param size [Integer] new length in bytes
    # @raise [Dave::NotFoundError] if parent collection does not exist
    def truncate(path, size) = raise NotImplementedError

    # Returns true if this provider can apply offset-aware writes and #truncate
    # without a whole-file rewrite. Defaults to false so providers that only
    # implement whole-file writes stay compliant without change; consumers then
    # fall back to a read-modify-write. Override to return true once
    # #write_content(offset:) and #truncate are implemented efficiently.
    # @return [Boolean]
    def supports_partial_writes? = false

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
