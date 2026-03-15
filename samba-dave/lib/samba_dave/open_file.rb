# frozen_string_literal: true

module SambaDave
  # Represents an open file or directory handle within an SMB2 session.
  #
  # Each CREATE request returns a FileId (16 bytes) that the client uses to
  # identify the file in subsequent READ, WRITE, CLOSE, QUERY_INFO, and
  # QUERY_DIRECTORY requests.
  #
  # An OpenFile holds:
  #   - file_id_bytes  — 16-byte binary string (persistent + volatile FileId)
  #   - path           — filesystem path, forward-slash separated, leading "/"
  #   - is_directory   — whether the handle refers to a directory
  #   - tree_connect   — parent TreeConnect (provides filesystem access)
  #   - position       — current byte offset for sequential reads/writes
  #   - enum_cursor    — position in directory enumeration (for QUERY_DIRECTORY)
  #
  class OpenFile
    attr_reader   :file_id_bytes, :path, :tree_connect
    attr_accessor :position, :enum_cursor, :delete_on_close

    # @param file_id_bytes [String] 16-byte binary FileId (persistent|volatile)
    # @param path [String] filesystem path (e.g. "/docs/report.pdf")
    # @param is_directory [Boolean] true if this handle refers to a directory
    # @param tree_connect [TreeConnect] parent tree connect
    def initialize(file_id_bytes:, path:, is_directory:, tree_connect:)
      @file_id_bytes  = file_id_bytes
      @path           = path
      @is_directory   = is_directory
      @tree_connect   = tree_connect
      @position       = 0
      @enum_cursor    = 0
      @delete_on_close = false
    end

    # @return [Boolean] true if this handle is for a directory
    def directory?
      @is_directory
    end

    # Convenience accessor — delegates to the parent tree connect.
    # @return [Object] the FileSystemProvider
    def filesystem
      @tree_connect.filesystem
    end
  end
end
