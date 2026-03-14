module Dave
  class Server
    module Handlers
      class PutHandler
        def initialize(filesystem, lock_manager, request)
          @filesystem   = filesystem
          @lock_manager = lock_manager
          @request      = request
        end

        def call
          path = @request.dav_path

          # Cannot PUT to a collection
          resource = @filesystem.get_resource(path)
          if resource&.collection?
            return Response.method_not_allowed
          end

          existed = !resource.nil?

          begin
            etag = @filesystem.write_content(
              path,
              @request.body,
              content_type: @request.content_type
            )
          rescue Dave::NotFoundError
            return Response.conflict
          end

          status  = existed ? 204 : 201
          headers = existed ? {} : { "ETag" => etag }
          Response.build(status, headers, "")
        end
      end
    end
  end
end
