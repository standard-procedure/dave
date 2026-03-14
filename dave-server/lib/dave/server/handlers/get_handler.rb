module Dave
  class Server
    module Handlers
      class GetHandler
        def initialize(filesystem, request, head: false)
          @filesystem = filesystem
          @request    = request
          @head       = head
        end

        def call
          path     = @request.dav_path
          resource = @filesystem.get_resource(path)

          return Response.not_found unless resource

          headers = {
            "Last-Modified" => resource.last_modified.httpdate,
            "ETag"          => resource.etag,
          }

          unless resource.collection?
            headers["Content-Type"]   = resource.content_type || "application/octet-stream"
            headers["Content-Length"] = resource.content_length.to_s
          end

          # ETag conditional: If-None-Match
          if_none_match = @request.get_header("HTTP_IF_NONE_MATCH")
          if if_none_match && etag_matches?(if_none_match, resource.etag)
            return Response.build(304, headers, "")
          end

          body = if @head || resource.collection?
            ""
          else
            io = @filesystem.read_content(path)
            io.respond_to?(:read) ? io.read : io
          end

          Response.build(200, headers, body)
        end

        private

        def etag_matches?(if_none_match, etag)
          # Handle "W/" weak ETags and wildcard
          if_none_match == "*" || if_none_match == etag ||
            if_none_match.split(",").map(&:strip).include?(etag)
        end
      end
    end
  end
end
