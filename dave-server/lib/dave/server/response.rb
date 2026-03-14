require "time"

module Dave
  class Server
    module Response
      HEADERS = {
        "Content-Type" => "text/plain",
      }.freeze

      def self.build(status, headers = {}, body = "")
        merged = HEADERS.merge(headers)
        merged["Date"] = Time.now.httpdate unless merged["Date"]
        body_array = body.is_a?(Array) ? body : [body.to_s]
        [status, merged, body_array]
      end

      def self.not_found
        build(404, {}, "Not Found")
      end

      def self.method_not_allowed
        build(405, {}, "Method Not Allowed")
      end

      def self.conflict
        build(409, {}, "Conflict")
      end

      def self.unsupported_media_type
        build(415, {}, "Unsupported Media Type")
      end

      def self.internal_error(msg = "Internal Server Error")
        build(500, {}, msg)
      end
    end
  end
end
