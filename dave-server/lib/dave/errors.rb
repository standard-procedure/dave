module Dave
  class Error < StandardError; end
  class NotFoundError < Error; end
  class AlreadyExistsError < Error; end
  class NotACollectionError < Error; end
  class LockedError < Error; end
  class InsufficientStorageError < Error; end
  class LockConflictError < Error; end
  class LockNotFoundError < Error; end
end
