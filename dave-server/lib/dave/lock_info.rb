module Dave
  # Represents an active write lock on a WebDAV resource.
  LockInfo = Struct.new(
    :token,       # String — lock token (UUID URN, e.g. "urn:uuid:...")
    :path,        # String — lock root path
    :scope,       # Symbol — :exclusive or :shared
    :type,        # Symbol — :write
    :depth,       # Symbol — :zero or :infinity
    :owner,       # String, nil — XML owner fragment (stored verbatim)
    :timeout,     # Integer or Symbol — seconds or :infinite
    :principal,   # String, nil — authenticated user id who created the lock
    :created_at,  # Time
    keyword_init: true
  )
end
