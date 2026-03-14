require "uri"
require "rack"

module Dave
  class Server
    module Handlers
      class MoveHandler
        def initialize(filesystem, lock_manager, request)
          @filesystem   = filesystem
          @lock_manager = lock_manager
          @request      = request
        end

        def call
          src = @request.dav_path

          # Destination header is required
          raw_destination = @request.env["HTTP_DESTINATION"]
          return Response.build(400, {}, "Bad Request: missing Destination header") if raw_destination.nil? || raw_destination.strip.empty?

          dst = parse_destination(raw_destination)
          return Response.build(400, {}, "Bad Request: invalid Destination header") if dst.nil?

          # Self-move is forbidden
          return Response.build(403, {}, "Forbidden: source and destination are the same") if src == dst

          overwrite = parse_overwrite(@request.env["HTTP_OVERWRITE"])

          begin
            result = @filesystem.move(src, dst, overwrite: overwrite)
          rescue Dave::AlreadyExistsError
            return Response.build(412, {}, "Precondition Failed: destination exists and Overwrite is F")
          rescue Dave::NotFoundError
            # Distinguish: if source doesn't exist → 404; if destination parent doesn't exist → 409
            resource = @filesystem.get_resource(src)
            if resource.nil?
              return Response.not_found
            else
              return Response.conflict
            end
          end

          status = result == :created ? 201 : 204
          Response.build(status, {}, "")
        end

        private

        def parse_destination(raw)
          uri = URI.parse(raw)
          path = uri.path
          return nil if path.nil? || path.empty?
          Rack::Utils.unescape_path(path)
        rescue URI::InvalidURIError
          nil
        end

        def parse_overwrite(header)
          case header
          when "F" then false
          else          true
          end
        end
      end
    end
  end
end
