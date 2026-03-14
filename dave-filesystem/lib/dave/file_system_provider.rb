require "dave/resource"
require "dave/errors"
require "dave/file_system_interface"
require "digest"
require "fileutils"
require "json"

module Dave
  class FileSystemProvider
    include Dave::FileSystemInterface

    def initialize(root:)
      @root = File.expand_path(root)
    end

    # ──────────────────────────────────────────────
    # Group C1: get_resource / list_children
    # ──────────────────────────────────────────────

    def get_resource(path)
      abs = absolute(path)
      return nil unless File.exist?(abs)

      build_resource(path, abs)
    end

    def list_children(path)
      abs = absolute(path)
      return nil unless File.exist?(abs)
      return nil unless File.directory?(abs)

      entries = Dir.entries(abs).reject { |e| e == "." || e == ".." }
      entries.map do |name|
        child_abs = File.join(abs, name)
        child_path = path.chomp("/") + "/" + name
        child_path += "/" if File.directory?(child_abs)
        build_resource(child_path, child_abs)
      end
    end

    # ──────────────────────────────────────────────
    # Group C2: read_content / write_content
    # ──────────────────────────────────────────────

    def read_content(path)
      abs = absolute(path)
      raise Dave::NotFoundError, "Resource not found: #{path}" unless File.exist?(abs)

      File.open(abs, "rb")
    end

    def write_content(path, io, content_type: nil)
      abs = absolute(path)
      parent = File.dirname(abs)
      raise Dave::NotFoundError, "Parent directory not found for: #{path}" unless File.directory?(parent)

      content = io.read
      File.open(abs, "wb") { |f| f.write(content) }
      '"' + Digest::MD5.hexdigest(content) + '"'
    end

    # ──────────────────────────────────────────────
    # Group C3: create_collection / delete
    # ──────────────────────────────────────────────

    def create_collection(path)
      abs = absolute(path)
      raise Dave::AlreadyExistsError, "Already exists: #{path}" if File.exist?(abs)

      parent = File.dirname(abs)
      raise Dave::NotFoundError, "Parent directory not found for: #{path}" unless File.directory?(parent)

      Dir.mkdir(abs)
    end

    def delete(path)
      abs = absolute(path)
      raise Dave::NotFoundError, "Resource not found: #{path}" unless File.exist?(abs)

      if File.directory?(abs)
        FileUtils.rm_rf(abs)
      else
        File.delete(abs)
      end
      []
    end

    # ──────────────────────────────────────────────
    # Group C4: locking / quota
    # ──────────────────────────────────────────────

    def supports_locking?
      false
    end

    def quota_available_bytes(path)
      nil
    end

    def quota_used_bytes(path)
      nil
    end

    # ──────────────────────────────────────────────
    # Phase 2: properties (persistent sidecar JSON files)
    # ──────────────────────────────────────────────

    def get_properties(path)
      sp = sidecar_path(path)
      return {} unless File.exist?(sp)

      JSON.parse(File.read(sp))
    rescue JSON::ParserError
      {}
    end

    def set_properties(path, properties)
      abs = absolute(path)
      raise Dave::NotFoundError, "Resource not found: #{path}" unless File.exist?(abs)

      sp = sidecar_path(path)
      FileUtils.mkdir_p(File.dirname(sp))

      existing = if File.exist?(sp)
        JSON.parse(File.read(sp))
      else
        {}
      end

      merged = existing.merge(properties)
      File.write(sp, JSON.generate(merged))
      properties
    end

    def delete_properties(path, names)
      abs = absolute(path)
      raise Dave::NotFoundError, "Resource not found: #{path}" unless File.exist?(abs)

      sp = sidecar_path(path)
      return unless File.exist?(sp)

      existing = JSON.parse(File.read(sp))
      names.each { |name| existing.delete(name) }
      File.write(sp, JSON.generate(existing))
      nil
    end

    # ──────────────────────────────────────────────
    # Phase 3 stubs: copy / move
    # ──────────────────────────────────────────────

    def copy(src, dst, depth: :infinity, overwrite: true)
      abs_src = absolute(src)
      abs_dst = absolute(dst)

      raise Dave::NotFoundError unless File.exist?(abs_src)
      raise Dave::NotFoundError unless File.exist?(File.dirname(abs_dst))
      raise Dave::AlreadyExistsError if !overwrite && File.exist?(abs_dst)

      existed = File.exist?(abs_dst)

      if File.directory?(abs_src)
        if depth == :zero
          FileUtils.mkdir_p(abs_dst)
        else
          FileUtils.cp_r(abs_src, abs_dst)
        end
      else
        FileUtils.cp(abs_src, abs_dst)
      end

      existed ? :no_content : :created
    end

    def move(src, dst, overwrite: true)
      abs_src = absolute(src)
      abs_dst = absolute(dst)

      raise Dave::NotFoundError unless File.exist?(abs_src)
      raise Dave::NotFoundError unless File.exist?(File.dirname(abs_dst))
      raise Dave::AlreadyExistsError if !overwrite && File.exist?(abs_dst)

      existed = File.exist?(abs_dst)
      FileUtils.mv(abs_src, abs_dst)
      existed ? :no_content : :created
    end

    # ──────────────────────────────────────────────
    # Phase 4 stubs: locking
    # ──────────────────────────────────────────────

    def lock(path, scope:, depth:, owner: nil, timeout: 3600) = raise NotImplementedError
    def unlock(path, token) = raise NotImplementedError
    def get_lock(path) = raise NotImplementedError

    private

    # Converts a resource path to its sidecar JSON file path inside .dave-props/.
    #
    # Examples (given @root = "/data"):
    #   /documents/report.pdf  →  /data/.dave-props/documents/report.pdf.json
    #   /documents/            →  /data/.dave-props/documents/.json
    #   /                      →  /data/.dave-props/.json
    def sidecar_path(path)
      # Normalise: strip leading slash, preserve trailing slash as a marker
      is_collection = path.end_with?("/")
      stripped = path.sub(%r{\A/}, "").sub(%r{/\z}, "")

      if stripped.empty?
        # Root collection: /.json inside .dave-props
        File.join(@root, ".dave-props", ".json")
      elsif is_collection
        # Collection: dir/.json
        File.join(@root, ".dave-props", stripped, ".json")
      else
        # File: path.json
        File.join(@root, ".dave-props", stripped + ".json")
      end
    end

    def absolute(path)
      expanded = File.expand_path(File.join(@root, path))
      unless expanded == @root || expanded.start_with?(@root + "/")
        raise Dave::NotFoundError, "Path outside root: #{path}"
      end
      expanded
    end

    def build_resource(path, abs)
      is_dir = File.directory?(abs)
      mtime = File.mtime(abs)
      created = begin
        File.birthtime(abs)
      rescue NotImplementedError
        mtime
      end

      etag = if is_dir
        '"' + Digest::MD5.hexdigest(abs + mtime.to_s) + '"'
      else
        '"' + Digest::MD5.file(abs).hexdigest + '"'
      end

      Dave::Resource.new(
        path: path,
        collection: is_dir,
        content_type: is_dir ? nil : mime_type_for(path),
        content_length: is_dir ? nil : File.size(abs),
        etag: etag,
        last_modified: mtime,
        created_at: created
      )
    end

    MIME_TYPES = {
      ".txt"  => "text/plain",
      ".html" => "text/html",
      ".htm"  => "text/html",
      ".css"  => "text/css",
      ".js"   => "application/javascript",
      ".json" => "application/json",
      ".xml"  => "application/xml",
      ".pdf"  => "application/pdf",
      ".png"  => "image/png",
      ".jpg"  => "image/jpeg",
      ".jpeg" => "image/jpeg",
      ".gif"  => "image/gif",
      ".svg"  => "image/svg+xml",
      ".zip"  => "application/zip",
      ".gz"   => "application/gzip",
    }.freeze

    def mime_type_for(path)
      ext = File.extname(path).downcase
      MIME_TYPES.fetch(ext, "application/octet-stream")
    end
  end
end
