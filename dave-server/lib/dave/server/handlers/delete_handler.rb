require "nokogiri"

module Dave
  class Server
    module Handlers
      class DeleteHandler
        include LockChecking

        def initialize(filesystem, lock_manager, request)
          @filesystem   = filesystem
          @lock_manager = lock_manager
          @request      = request
        end

        def call
          path = @request.dav_path

          return Response.build(423, {}, "Locked") if locked_without_token?(path)

          begin
            failed = @filesystem.delete(path)
          rescue Dave::NotFoundError
            return Response.not_found
          end

          if failed.empty?
            Response.build(204, {}, "")
          else
            # 207 Multi-Status for partial failure
            xml = build_multistatus(failed)
            Response.build(207, { "Content-Type" => "application/xml" }, xml)
          end
        end

        private

        def build_multistatus(failed_paths)
          builder = Nokogiri::XML::Builder.new(encoding: "UTF-8") do |xml|
            xml.multistatus("xmlns" => "DAV:") do
              failed_paths.each do |p|
                xml.response do
                  xml.href(p)
                  xml.status("HTTP/1.1 500 Internal Server Error")
                end
              end
            end
          end
          builder.to_xml
        end
      end
    end
  end
end
