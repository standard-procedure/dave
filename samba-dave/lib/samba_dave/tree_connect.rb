# frozen_string_literal: true

module SambaDave
  # Represents an active SMB2 tree connect (mounted share).
  #
  # Each authenticated session can have multiple tree connects — one per share
  # that the client has connected to. Tree connects are identified by a TreeId
  # assigned by the server during TREE_CONNECT.
  #
  # A TreeConnect holds:
  #   - tree_id     — the 32-bit identifier sent in subsequent SMB2 headers
  #   - share_name  — the share name as presented to the client
  #   - filesystem  — the FileSystemProvider to call for file operations
  #
  class TreeConnect
    attr_reader :tree_id, :share_name, :filesystem

    # @param tree_id [Integer] 32-bit tree connect identifier
    # @param share_name [String] share name (from UNC path)
    # @param filesystem [Object] FileSystemProvider instance (Dave::FileSystemProvider or compatible)
    def initialize(tree_id:, share_name:, filesystem:)
      @tree_id    = tree_id
      @share_name = share_name
      @filesystem = filesystem
    end
  end
end
