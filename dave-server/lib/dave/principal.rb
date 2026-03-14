module Dave
  # Immutable value object representing an authenticated user.
  # id           — unique identifier (e.g. username)
  # display_name — human-readable name for DAV:owner display
  Principal = Data.define(:id, :display_name)
end
