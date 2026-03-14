module Dave
  class Server
    module Handlers
      class MkcolHandler
        include LockChecking

        def initialize(filesystem, lock_manager, request)
          @filesystem   = filesystem
          @lock_manager = lock_manager
          @request      = request
        end

        def call
          path = @request.dav_path

          # RFC 4918: MKCOL with non-empty request body → 415
          body = @request.body
          if body
            body_content = body.read
            body.rewind
            return Response.unsupported_media_type unless body_content.empty?
          end

          return Response.build(423, {}, "Locked") if locked_without_token?(path)

          begin
            @filesystem.create_collection(path)
          rescue Dave::AlreadyExistsError
            return Response.method_not_allowed
          rescue Dave::NotFoundError
            return Response.conflict
          end

          Response.build(201, {}, "")
        end
      end
    end
  end
end
