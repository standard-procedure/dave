require "nokogiri"

module Dave
  class Server
    module Handlers
      class ProppatchHandler
        include LockChecking

        def initialize(filesystem, lock_manager, request)
          @filesystem   = filesystem
          @lock_manager = lock_manager
          @request      = request
        end

        def call
          path = @request.dav_path

          # Resource must exist
          resource = @filesystem.get_resource(path)
          return Response.not_found unless resource

          return Response.build(423, {}, "Locked") if locked_without_token?(path)

          # Parse the request body
          body = @request.body.read

          # Empty body is a 400 for PROPPATCH (unlike PROPFIND which defaults to allprop)
          if body.nil? || body.strip.empty?
            return Response.build(400, {}, "Bad Request: body required for PROPPATCH")
          end

          result = parse_request(body)
          return Response.build(400, {}, "Bad Request: malformed XML") if result == :bad_request

          set_props, remove_names = result

          # Collect all operations and check for live property violations
          all_ops = set_props.keys.map { |n| { name: n, op: :set } } +
                    remove_names.map    { |n| { name: n, op: :remove } }

          forbidden_names = all_ops.select { |op| Dave::Properties.live?(op[:name]) }.map { |op| op[:name] }
          allowed_names   = all_ops.reject { |op| Dave::Properties.live?(op[:name]) }.map { |op| op[:name] }

          propstats = if forbidden_names.any?
            build_failure_propstats(forbidden_names, allowed_names)
          else
            # Apply changes atomically
            @filesystem.set_properties(path, set_props) unless set_props.empty?
            @filesystem.delete_properties(path, remove_names) unless remove_names.empty?

            all_prop_names = set_props.keys + remove_names
            [{ props: all_prop_names.each_with_object({}) { |n, h| h[n] = "" }, status: 200 }]
          end

          xml = Dave::XML.multistatus([{ href: path, propstats: propstats }])
          Response.build(207, { "Content-Type" => "application/xml" }, xml)
        end

        private

        # Parse the propertyupdate XML body.
        # Returns [set_props_hash, remove_names_array] on success, or :bad_request on error.
        def parse_request(body)
          doc = Nokogiri::XML(body) { |config| config.strict }
          return :bad_request if doc.errors.any?

          set_props = {}
          doc.xpath("//D:set/D:prop/*", "D" => "DAV:").each do |node|
            clark_name = "{#{node.namespace&.href}}#{node.name}"
            value = if node.children.any?(&:element?)
              node.children.map(&:to_xml).join
            else
              node.text
            end
            set_props[clark_name] = value
          end

          remove_names = []
          doc.xpath("//D:remove/D:prop/*", "D" => "DAV:").each do |node|
            remove_names << "{#{node.namespace&.href}}#{node.name}"
          end

          [set_props, remove_names]
        rescue Nokogiri::XML::SyntaxError
          :bad_request
        end

        def build_failure_propstats(forbidden_names, allowed_names)
          propstats = []
          propstats << {
            props: forbidden_names.each_with_object({}) { |n, h| h[n] = "" },
            status: 403
          }
          if allowed_names.any?
            propstats << {
              props: allowed_names.each_with_object({}) { |n, h| h[n] = "" },
              status: 424
            }
          end
          propstats
        end
      end
    end
  end
end
