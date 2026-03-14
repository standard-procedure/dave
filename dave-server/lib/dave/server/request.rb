require "rack"

module Dave
  class Server
    class Request < Rack::Request
      # Returns the URL-decoded path, stripped of any server prefix.
      # Always starts with "/".
      # Collection paths end with "/" UNLESS the underlying resource
      # is not a collection (determined later by the filesystem).
      def dav_path
        raw = path_info
        decoded = Rack::Utils.unescape_path(raw)
        # Normalize: ensure single leading slash
        decoded.start_with?("/") ? decoded : "/#{decoded}"
      end
    end
  end
end
