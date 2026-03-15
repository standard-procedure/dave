# frozen_string_literal: true

require "securerandom"

module SambaDave
  # Thread-safe table mapping FileId → OpenFile.
  #
  # Each Connection maintains one OpenFileTable. FileIds are 16-byte binary
  # strings (two uint64 fields: persistent + volatile). The table generates
  # unique FileIds on demand.
  #
  class OpenFileTable
    def initialize
      @table = {}
      @mutex = Mutex.new
    end

    # Generate a unique 16-byte FileId (8 bytes persistent + 8 bytes volatile).
    # For SMB 2.0.2 there are no durable handles, so both halves are random.
    #
    # @return [String] 16 random bytes (binary encoding)
    def generate_file_id
      SecureRandom.bytes(16)
    end

    # Add an OpenFile to the table, keyed by its file_id_bytes.
    #
    # @param open_file [OpenFile]
    def add(open_file)
      @mutex.synchronize { @table[open_file.file_id_bytes] = open_file }
    end

    # Retrieve an OpenFile by its 16-byte FileId.
    #
    # @param file_id_bytes [String] 16-byte binary FileId
    # @return [OpenFile, nil]
    def get(file_id_bytes)
      @mutex.synchronize { @table[file_id_bytes] }
    end

    # Remove an OpenFile from the table. Silently ignores unknown FileIds.
    #
    # @param file_id_bytes [String] 16-byte binary FileId
    def remove(file_id_bytes)
      @mutex.synchronize { @table.delete(file_id_bytes) }
    end

    # @return [Integer] number of currently open handles
    def size
      @mutex.synchronize { @table.size }
    end
  end
end
