require "nokogiri"

module Dave
  class Server
    module Handlers
      class PropfindHandler
        FINITE_DEPTH_ERROR = <<~XML.freeze
          <?xml version="1.0" encoding="UTF-8"?>
          <D:error xmlns:D="DAV:"><D:propfind-finite-depth/></D:error>
        XML

        def initialize(filesystem, request)
          @filesystem = filesystem
          @request    = request
        end

        def call
          depth = parse_depth
          return Response.build(400, {}, "Invalid Depth header") if depth == :invalid
          return forbidden_infinite_depth unless depth

          path     = @request.dav_path
          resource = @filesystem.get_resource(path)
          return Response.not_found unless resource

          body    = @request.body.read
          request_type = parse_request_type(body)
          return Response.build(400, {}, "Bad Request") if request_type == :bad_request

          resources = collect_resources(path, resource, depth)
          responses = build_responses(resources, request_type)

          xml = Dave::XML.multistatus(responses)
          Response.build(207, { "Content-Type" => "application/xml" }, xml)
        end

        private

        # Returns the Depth as an integer (0 or 1), nil for infinity/missing, or :invalid for unknown values.
        def parse_depth
          raw = @request.get_header("HTTP_DEPTH")
          case raw
          when "0"        then 0
          when "1"        then 1
          when "infinity" then nil
          when nil        then nil      # missing header → treat as infinity
          else                 :invalid # unknown value → 400 Bad Request
          end
        end

        def forbidden_infinite_depth
          Response.build(
            403,
            { "Content-Type" => "application/xml" },
            FINITE_DEPTH_ERROR
          )
        end

        # Parse the request body and return one of:
        #   :allprop
        #   :propname
        #   [:prop, [clark_name, ...]]
        #   :bad_request
        def parse_request_type(body)
          return :allprop if body.nil? || body.strip.empty?

          doc = Nokogiri::XML(body) { |config| config.strict }
          return :bad_request if doc.errors.any?

          if doc.at_xpath("//D:allprop", "D" => "DAV:")
            :allprop
          elsif doc.at_xpath("//D:propname", "D" => "DAV:")
            :propname
          else
            prop_names = doc.xpath("//D:prop/*", "D" => "DAV:").map do |node|
              ns_href = node.namespace&.href || "DAV:"
              "{#{ns_href}}#{node.name}"
            end
            [:prop, prop_names]
          end
        rescue Nokogiri::XML::SyntaxError
          :bad_request
        end

        # Collect resources based on depth.
        # Returns array of [path, resource] pairs.
        def collect_resources(path, resource, depth)
          resources = [[path, resource]]

          if depth == 1 && resource.collection?
            children = @filesystem.list_children(path) || []
            children.each do |child|
              child_path = child.path
              resources << [child_path, child]
            end
          end

          resources
        end

        # Build the responses array for Dave::XML.multistatus.
        def build_responses(resources, request_type)
          resources.map do |path, resource|
            propstats = build_propstats(path, resource, request_type)
            { href: path, propstats: propstats }
          end
        end

        # Build propstats for a single resource.
        def build_propstats(path, resource, request_type)
          live_props = Dave::Properties.live_properties(resource)
          dead_props = @filesystem.get_properties(path)

          case request_type
          when :allprop
            all_props = live_props.merge(dead_props)
            [{ props: all_props, status: 200 }]

          when :propname
            # All property names with empty values
            all_names = (live_props.keys + dead_props.keys).uniq
            names_hash = all_names.each_with_object({}) { |n, h| h[n] = "" }
            [{ props: names_hash, status: 200 }]

          else
            # [:prop, [clark_names...]]
            _, requested_names = request_type
            all_available = live_props.merge(dead_props)

            found   = {}
            missing = {}

            requested_names.each do |name|
              if all_available.key?(name)
                found[name] = all_available[name]
              else
                missing[name] = ""
              end
            end

            propstats = []
            propstats << { props: found,   status: 200 } unless found.empty?
            propstats << { props: missing, status: 404 } unless missing.empty?
            propstats
          end
        end
      end
    end
  end
end
