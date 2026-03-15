require "spec_helper"
require "digest"
require "stringio"
require "set"

module Dave
  # In-memory filesystem provider backed by a Hash.
  # Thread-safe via Mutex.
  #
  # Usage:
  #   provider = Dave::InMemoryProvider.new
  #   server = Dave::Server.new(filesystem: provider)
  class InMemoryProvider
    include Dave::FileSystemInterface

    def initialize
      @mutex = Mutex.new
      # Storage for file entries:
      # @files[path] = { content: String, content_type: String, etag: String,
      #                  last_modified: Time, created_at: Time }
      @files = {}
      # Storage for collection entries: Set of known collection paths
      @collections = Set.new
      # Dead properties: @properties[path] = { clark_name => xml_value_string }
      @properties = Hash.new { |h, k| h[k] = {} }

      # Root collection always exists
      @collections.add("/")
    end

    # -------------------------------------------------------------------------
    # Resource query
    # -------------------------------------------------------------------------

    def get_resource(path)
      @mutex.synchronize do
        if @collections.include?(path)
          Dave::Resource.new(
            path: path,
            collection: true,
            content_type: nil,
            content_length: nil,
            etag: collection_etag(path),
            last_modified: Time.now,
            created_at: Time.now
          )
        elsif @files.key?(path)
          entry = @files[path]
          Dave::Resource.new(
            path: path,
            collection: false,
            content_type: entry[:content_type] || "application/octet-stream",
            content_length: entry[:content].bytesize,
            etag: entry[:etag],
            last_modified: entry[:last_modified],
            created_at: entry[:created_at]
          )
        end
      end
    end

    def list_children(path)
      @mutex.synchronize do
        return nil unless @collections.include?(path)

        prefix = path.end_with?("/") ? path : "#{path}/"
        children = []

        (@collections + @files.keys).each do |p|
          next if p == path
          # Direct child: starts with prefix, no further "/" after the prefix
          remainder = p.delete_prefix(prefix)
          next if remainder.empty?
          # A direct child has no slash (file) or only a trailing slash (collection)
          next if remainder.tr("/", "").length != remainder.length - (remainder.end_with?("/") ? 1 : 0)
          next if remainder.count("/") > (remainder.end_with?("/") ? 1 : 0)

          resource = get_resource_unlocked(p)
          children << resource if resource
        end

        children
      end
    end

    # -------------------------------------------------------------------------
    # Read / Write
    # -------------------------------------------------------------------------

    def read_content(path)
      @mutex.synchronize do
        raise Dave::NotFoundError, "Not found: #{path}" unless @files.key?(path)

        StringIO.new(@files[path][:content].dup)
      end
    end

    def write_content(path, content, content_type: nil)
      parent = parent_path(path)
      @mutex.synchronize do
        raise Dave::NotFoundError, "Parent not found: #{parent}" unless @collections.include?(parent)

        body = content.read
        etag = %("#{Digest::MD5.hexdigest(body)}")
        now = Time.now

        @files[path] = {
          content: body,
          content_type: content_type || "application/octet-stream",
          etag: etag,
          last_modified: now,
          created_at: @files.dig(path, :created_at) || now
        }
        etag
      end
    end

    def create_collection(path)
      parent = parent_path(path)
      @mutex.synchronize do
        raise Dave::AlreadyExistsError, "Already exists: #{path}" if @collections.include?(path) || @files.key?(path)
        raise Dave::NotFoundError, "Parent not found: #{parent}" unless @collections.include?(parent)

        @collections.add(path)
      end
    end

    # -------------------------------------------------------------------------
    # Delete
    # -------------------------------------------------------------------------

    def delete(path)
      @mutex.synchronize do
        raise Dave::NotFoundError, "Not found: #{path}" unless @collections.include?(path) || @files.key?(path)

        failed = []

        if @collections.include?(path)
          # Delete all descendants first
          prefix = path.end_with?("/") ? path : "#{path}/"
          @files.keys.select { |p| p.start_with?(prefix) }.each do |p|
            @files.delete(p)
            @properties.delete(p)
          end
          @collections.select { |p| p.start_with?(prefix) }.each { |p| @collections.delete(p) }
          @collections.delete(path)
          @properties.delete(path)
        else
          @files.delete(path)
          @properties.delete(path)
        end

        failed
      end
    end

    # -------------------------------------------------------------------------
    # Copy / Move
    # -------------------------------------------------------------------------

    def copy(src, dst, depth: :infinity, overwrite: true)
      @mutex.synchronize do
        raise Dave::NotFoundError, "Source not found: #{src}" unless exists_unlocked?(src)

        dst_parent = parent_path(dst)
        raise Dave::NotFoundError, "Destination parent not found: #{dst_parent}" unless @collections.include?(dst_parent)

        dst_existed = exists_unlocked?(dst)
        raise Dave::AlreadyExistsError, "Destination exists: #{dst}" if !overwrite && dst_existed

        delete_unlocked(dst) if dst_existed

        if @collections.include?(src)
          @collections.add(dst)
          @properties[dst] = @properties[src].dup

          if depth == :infinity
            prefix = src.end_with?("/") ? src : "#{src}/"
            dst_prefix = dst.end_with?("/") ? dst : "#{dst}/"

            @collections.select { |p| p.start_with?(prefix) }.each do |p|
              new_path = dst_prefix + p.delete_prefix(prefix)
              @collections.add(new_path)
              @properties[new_path] = @properties[p].dup
            end
            @files.select { |p, _| p.start_with?(prefix) }.each do |p, entry|
              new_path = dst_prefix + p.delete_prefix(prefix)
              @files[new_path] = entry.dup
              @properties[new_path] = @properties[p].dup
            end
          end
        else
          @files[dst] = @files[src].dup
          @properties[dst] = @properties[src].dup
        end

        dst_existed ? :no_content : :created
      end
    end

    def move(src, dst, overwrite: true)
      result = copy(src, dst, depth: :infinity, overwrite: overwrite)
      @mutex.synchronize { delete_unlocked(src) }
      result
    end

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    def get_properties(path)
      @mutex.synchronize do
        @properties[path].dup
      end
    end

    def set_properties(path, properties)
      @mutex.synchronize do
        raise Dave::NotFoundError, "Not found: #{path}" unless exists_unlocked?(path)

        @properties[path].merge!(properties)
      end
    end

    def delete_properties(path, names)
      @mutex.synchronize do
        raise Dave::NotFoundError, "Not found: #{path}" unless exists_unlocked?(path)

        names.each { |name| @properties[path].delete(name) }
      end
    end

    # -------------------------------------------------------------------------
    # Locking (not supported)
    # -------------------------------------------------------------------------

    def lock(path, scope:, depth:, owner: nil, timeout: 3600)
      raise NotImplementedError, "Locking not supported by InMemoryProvider; use a provider that includes LockSupport"
    end

    def unlock(path, token)
      raise NotImplementedError
    end

    def get_lock(path)
      []
    end

    def supports_locking?
      false
    end

    # -------------------------------------------------------------------------
    # Quota (unknown for in-memory store)
    # -------------------------------------------------------------------------

    def quota_available_bytes(_path)
      nil
    end

    def quota_used_bytes(_path)
      nil
    end

    private

    def exists_unlocked?(path)
      @collections.include?(path) || @files.key?(path)
    end

    def get_resource_unlocked(path)
      if @collections.include?(path)
        Dave::Resource.new(
          path: path, collection: true, content_type: nil, content_length: nil,
          etag: collection_etag(path), last_modified: Time.now, created_at: Time.now
        )
      elsif @files.key?(path)
        e = @files[path]
        Dave::Resource.new(
          path: path, collection: false,
          content_type: e[:content_type], content_length: e[:content].bytesize,
          etag: e[:etag], last_modified: e[:last_modified], created_at: e[:created_at]
        )
      end
    end

    def delete_unlocked(path)
      if @collections.include?(path)
        prefix = path.end_with?("/") ? path : "#{path}/"
        @files.keys.select { |p| p.start_with?(prefix) }.each { |p| @files.delete(p); @properties.delete(p) }
        @collections.select { |p| p.start_with?(prefix) }.each { |p| @collections.delete(p) }
        @collections.delete(path)
        @properties.delete(path)
      else
        @files.delete(path)
        @properties.delete(path)
      end
    end

    def parent_path(path)
      stripped = path.chomp("/")
      return "/" if stripped.count("/") == 1

      "#{stripped.rpartition("/").first}/"
    end

    def collection_etag(path)
      contents = @collections.select { |p| p.start_with?(path) && p != path }.sort.join + @files.keys.select { |p| p.start_with?(path) }.sort.join
      %("#{Digest::MD5.hexdigest(contents)}")
    end
  end
end

RSpec.describe Dave::InMemoryProvider do
  subject { Dave::InMemoryProvider.new }

  include Dave::FileSystemInterface::ComplianceTests
end
