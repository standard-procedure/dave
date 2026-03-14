require "time"
require_relative "errors"
require_relative "principal"
require_relative "resource"
require_relative "lock_info"
require_relative "file_system_interface"
require_relative "security_interface"
require_relative "server/request"
require_relative "server/response"
require_relative "server/handlers/options_handler"
require_relative "server/handlers/get_handler"
require_relative "server/handlers/put_handler"
require_relative "server/handlers/mkcol_handler"
require_relative "server/handlers/delete_handler"
require_relative "xml"
require_relative "properties"

module Dave
  class Server
    VERSION = "0.1.0"

    ALLOWED_METHODS = %w[
      GET HEAD PUT DELETE MKCOL OPTIONS
      PROPFIND PROPPATCH COPY MOVE LOCK UNLOCK
    ].freeze

    def initialize(filesystem:, prefix: "")
      @filesystem = filesystem
      @prefix = prefix
    end

    def call(env)
      request = Request.new(env)
      method  = request.request_method.upcase

      case method
      when "OPTIONS"  then Handlers::OptionsHandler.new(@filesystem, request).call
      when "GET"      then Handlers::GetHandler.new(@filesystem, request).call
      when "HEAD"     then Handlers::GetHandler.new(@filesystem, request, head: true).call
      when "PUT"      then Handlers::PutHandler.new(@filesystem, request).call
      when "MKCOL"    then Handlers::MkcolHandler.new(@filesystem, request).call
      when "DELETE"   then Handlers::DeleteHandler.new(@filesystem, request).call
      else
        Response.build(501, {}, "Not Implemented")
      end
    rescue => e
      Response.build(500, {}, "Internal Server Error: #{e.message}")
    end
  end
end
