module Dave
  # Immutable value object representing a WebDAV resource.
  Resource = Data.define(
    :path,           # String — URL-decoded path; collection paths end with "/"
    :collection,     # Boolean — true if this is a collection (directory)
    :content_type,   # String, nil — MIME type; nil for collections
    :content_length, # Integer, nil — bytes; nil for collections
    :etag,           # String — strong ETag (quoted, e.g. '"abc123"')
    :last_modified,  # Time
    :created_at      # Time
  ) do
    alias_method :collection?, :collection
  end
end
