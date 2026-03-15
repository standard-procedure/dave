require "time"
require "base64"
require_relative "errors"
require_relative "principal"
require_relative "resource"
require_relative "lock_info"
require_relative "lock_manager"
require_relative "file_system_interface"
require_relative "security_interface"
require_relative "server/request"
require_relative "server/response"
require_relative "server/lock_checking"
require_relative "server/handlers/options_handler"
require_relative "server/handlers/get_handler"
require_relative "server/handlers/put_handler"
require_relative "server/handlers/mkcol_handler"
require_relative "server/handlers/delete_handler"
require_relative "server/handlers/propfind_handler"
require_relative "server/handlers/proppatch_handler"
require_relative "server/handlers/copy_handler"
require_relative "server/handlers/move_handler"
require_relative "server/handlers/lock_handler"
require_relative "server/handlers/unlock_handler"
require_relative "xml"
require_relative "properties"

module Dave
  class Server
    VERSION = "0.1.0"

    ALLOWED_METHODS = %w[
      GET HEAD PUT DELETE MKCOL OPTIONS
      PROPFIND PROPPATCH COPY MOVE LOCK UNLOCK
    ].freeze

    READ_METHODS  = %w[GET HEAD OPTIONS PROPFIND].freeze
    WRITE_METHODS = %w[PUT DELETE MKCOL PROPPATCH COPY MOVE LOCK UNLOCK].freeze

    def initialize(filesystem:, prefix: "", security: nil)
      @filesystem   = filesystem
      @prefix       = prefix
      @lock_manager = LockManager.new
      @security     = security
    end

    def call(env)
      request = Request.new(env)
      method  = request.request_method.upcase

      if @security
        auth_response = check_auth(request, method)
        return auth_response if auth_response
      end

      case method
      when "OPTIONS"  then Handlers::OptionsHandler.new(@filesystem, @lock_manager, request).call
      when "GET"      then Handlers::GetHandler.new(@filesystem, @lock_manager, request).call
      when "HEAD"     then Handlers::GetHandler.new(@filesystem, @lock_manager, request, head: true).call
      when "PUT"      then Handlers::PutHandler.new(@filesystem, @lock_manager, request).call
      when "MKCOL"    then Handlers::MkcolHandler.new(@filesystem, @lock_manager, request).call
      when "DELETE"   then Handlers::DeleteHandler.new(@filesystem, @lock_manager, request).call
      when "PROPFIND"   then Handlers::PropfindHandler.new(@filesystem, @lock_manager, request).call
      when "PROPPATCH"  then Handlers::ProppatchHandler.new(@filesystem, @lock_manager, request).call
      when "COPY"       then Handlers::CopyHandler.new(@filesystem, @lock_manager, request).call
      when "MOVE"       then Handlers::MoveHandler.new(@filesystem, @lock_manager, request).call
      when "LOCK"       then Handlers::LockHandler.new(@filesystem, @lock_manager, request).call
      when "UNLOCK"     then Handlers::UnlockHandler.new(@filesystem, @lock_manager, request).call
      else
        Response.build(501, {}, "Not Implemented")
      end
    rescue => e
      Response.build(500, {}, "Internal Server Error: #{e.message}")
    end

    private

    def check_auth(request, method)
      auth_header = request.get_header("HTTP_AUTHORIZATION")

      principal = if auth_header&.start_with?("Basic ")
        encoded = auth_header.sub("Basic ", "")
        decoded = Base64.decode64(encoded)
        username, password = decoded.split(":", 2)
        @security.authenticate(username: username, password: password)
      end

      unless principal
        return Response.build(401,
          { "WWW-Authenticate" => @security.challenge },
          "Unauthorized")
      end

      operation = if READ_METHODS.include?(method)
        :read
      else
        :write
      end

      unless @security.authorize(principal, request.path, operation)
        return Response.build(403, {}, "Forbidden")
      end

      nil
    end
  end
end
