module Dave
  class Server
    module Handlers
      class UnlockHandler
        LOCK_TOKEN_MISMATCH_ERROR = <<~XML.freeze
          <?xml version="1.0" encoding="UTF-8"?>
          <D:error xmlns:D="DAV:"><D:lock-token-matches-request-uri/></D:error>
        XML

        def initialize(filesystem, lock_manager, request)
          @filesystem   = filesystem
          @lock_manager = lock_manager
          @request      = request
        end

        def call
          token = extract_token
          return Response.build(400, {}, "Bad Request: missing Lock-Token header") if token.nil?

          path_locks = @lock_manager.locks_for(@request.dav_path)

          if path_locks.any? { |l| l.token == token }
            @lock_manager.release(token)
            Response.build(204, {}, "")
          else
            Response.build(
              409,
              { "Content-Type" => "application/xml" },
              LOCK_TOKEN_MISMATCH_ERROR
            )
          end
        end

        private

        def extract_token
          header = @request.get_header("HTTP_LOCK_TOKEN")
          return nil if header.nil?

          header.match(/<(urn:uuid:[^>]+)>/)&.captures&.first
        end
      end
    end
  end
end
