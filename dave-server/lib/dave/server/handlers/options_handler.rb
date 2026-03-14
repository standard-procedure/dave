module Dave
  class Server
    module Handlers
      class OptionsHandler
        def initialize(filesystem, request)
          @filesystem = filesystem
          @request    = request
        end

        def call
          Response.build(200, {
            "Allow"          => Dave::Server::ALLOWED_METHODS.join(", "),
            "DAV"            => "1",
            "Content-Length" => "0",
          }, "")
        end
      end
    end
  end
end
