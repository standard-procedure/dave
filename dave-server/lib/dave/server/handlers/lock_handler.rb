require "nokogiri"

module Dave
  class Server
    module Handlers
      class LockHandler
        LOCKED_ERROR = <<~XML.freeze
          <?xml version="1.0" encoding="UTF-8"?>
          <D:error xmlns:D="DAV:"><D:no-conflicting-lock/></D:error>
        XML

        def initialize(filesystem, lock_manager, request)
          @filesystem   = filesystem
          @lock_manager = lock_manager
          @request      = request
        end

        def call
          body = @request.body.read
          if_header = @request.get_header("HTTP_IF")

          if body.strip.empty? && if_header.nil?
            # No body and no If header — bad request
            return Response.build(400, {}, "Bad Request: missing lockinfo body")
          end

          if body.strip.empty? && if_header
            # Lock refresh
            refresh_lock(if_header)
          else
            # New lock
            create_lock(body)
          end
        end

        private

        # -----------------------------------------------------------------------
        # Lock creation
        # -----------------------------------------------------------------------
        def create_lock(body)
          lock_info = parse_lockinfo(body)
          return Response.build(400, {}, "Bad Request: malformed lockinfo XML") unless lock_info

          path   = @request.dav_path
          resource = @filesystem.get_resource(path)

          if resource.nil?
            # Create empty resource — parent must exist
            begin
              @filesystem.write_content(path, StringIO.new(""), content_type: "application/octet-stream")
            rescue Dave::NotFoundError
              return Response.conflict
            end
            status = 201
          else
            status = 200
          end

          depth   = parse_depth(lock_info[:depth])
          timeout = parse_timeout(@request.get_header("HTTP_TIMEOUT"))

          lock = begin
            @lock_manager.acquire(
              path,
              scope:    lock_info[:scope],
              depth:    depth,
              owner:    lock_info[:owner],
              timeout:  timeout,
              principal: nil
            )
          rescue Dave::LockConflictError
            return Response.build(
              423,
              { "Content-Type" => "application/xml" },
              LOCKED_ERROR
            )
          end

          xml = build_lock_response_xml(lock)
          Response.build(
            status,
            {
              "Content-Type" => "application/xml",
              "Lock-Token"   => "<#{lock.token}>"
            },
            xml
          )
        end

        # -----------------------------------------------------------------------
        # Lock refresh
        # -----------------------------------------------------------------------
        def refresh_lock(if_header)
          tokens = if_header.scan(/<(urn:uuid:[^>]+)>/).flatten
          return Response.build(412, {}, "Precondition Failed: no lock token in If header") if tokens.empty?

          token   = tokens.first
          timeout = parse_timeout(@request.get_header("HTTP_TIMEOUT"))

          lock = begin
            @lock_manager.refresh(token, timeout: timeout)
          rescue Dave::LockNotFoundError
            return Response.build(412, {}, "Precondition Failed: lock token not found or expired")
          end

          xml = build_lock_response_xml(lock)
          Response.build(
            200,
            { "Content-Type" => "application/xml" },
            xml
          )
        end

        # -----------------------------------------------------------------------
        # XML parsing
        # -----------------------------------------------------------------------

        # Returns { scope:, depth:, owner: } or nil on parse error.
        def parse_lockinfo(body)
          doc = Nokogiri::XML(body) { |config| config.strict }
          return nil if doc.errors.any?

          ns = { "D" => "DAV:" }

          scope_node = doc.at_xpath("//D:lockscope/*[1]", ns)
          return nil unless scope_node

          scope = case scope_node.name
                  when "exclusive" then :exclusive
                  when "shared"    then :shared
                  else return nil
                  end

          # Depth from request header (not body), but we track that the body
          # has been read and is valid. Depth defaults are handled in parse_depth.
          depth_raw = @request.get_header("HTTP_DEPTH")

          # Owner: capture the entire inner XML of <D:owner> if present
          owner_node = doc.at_xpath("//D:owner", ns)
          owner = owner_node ? owner_node.inner_html.strip : nil

          { scope: scope, depth: depth_raw, owner: owner }
        rescue Nokogiri::XML::SyntaxError
          nil
        end

        # Returns :zero or :infinity. Default is :infinity per RFC 4918.
        def parse_depth(depth_raw)
          case depth_raw
          when "0"        then :zero
          when "infinity" then :infinity
          when nil        then :infinity
          else :infinity
          end
        end

        # Returns integer seconds or :infinite. Default is 3600.
        def parse_timeout(raw)
          return 3600 if raw.nil?

          case raw.strip
          when /\AInfinite\z/i then :infinite
          when /\ASecond-(\d+)\z/i
            $1.to_i
          else
            3600
          end
        end

        # -----------------------------------------------------------------------
        # XML response builder
        # -----------------------------------------------------------------------
        def build_lock_response_xml(lock)
          doc = Nokogiri::XML::Document.new
          doc.encoding = "UTF-8"

          prop = doc.create_element("prop")
          dav_ns = prop.add_namespace_definition("D", "DAV:")
          prop.namespace = dav_ns
          doc.root = prop

          lockdiscovery = doc.create_element("lockdiscovery")
          lockdiscovery.namespace = dav_ns
          prop.add_child(lockdiscovery)

          activelock = doc.create_element("activelock")
          activelock.namespace = dav_ns
          lockdiscovery.add_child(activelock)

          # locktype
          locktype = doc.create_element("locktype")
          locktype.namespace = dav_ns
          write_el = doc.create_element("write")
          write_el.namespace = dav_ns
          locktype.add_child(write_el)
          activelock.add_child(locktype)

          # lockscope
          lockscope = doc.create_element("lockscope")
          lockscope.namespace = dav_ns
          scope_el = doc.create_element(lock.scope.to_s)
          scope_el.namespace = dav_ns
          lockscope.add_child(scope_el)
          activelock.add_child(lockscope)

          # depth
          depth_el = doc.create_element("depth")
          depth_el.namespace = dav_ns
          depth_el.content = lock.depth == :zero ? "0" : "infinity"
          activelock.add_child(depth_el)

          # owner (optional)
          if lock.owner && !lock.owner.empty?
            owner_el = doc.create_element("owner")
            owner_el.namespace = dav_ns
            # Parse the stored inner XML and import children using holder trick
            wrapper = Nokogiri::XML("<wrapper xmlns:D=\"DAV:\">#{lock.owner}</wrapper>")
            wrapper.root.children.each do |child|
              holder = doc.create_element("_holder")
              copy = child.dup
              holder.add_child(copy)
              imported = holder.children.first
              rebind_dav_ns(imported, dav_ns)
              owner_el.add_child(imported)
            end
            activelock.add_child(owner_el)
          end

          # timeout
          timeout_el = doc.create_element("timeout")
          timeout_el.namespace = dav_ns
          timeout_el.content = lock.timeout == :infinite ? "Infinite" : "Second-#{lock.timeout}"
          activelock.add_child(timeout_el)

          # locktoken
          locktoken = doc.create_element("locktoken")
          locktoken.namespace = dav_ns
          token_href = doc.create_element("href")
          token_href.namespace = dav_ns
          token_href.content = lock.token
          locktoken.add_child(token_href)
          activelock.add_child(locktoken)

          # lockroot
          lockroot = doc.create_element("lockroot")
          lockroot.namespace = dav_ns
          root_href = doc.create_element("href")
          root_href.namespace = dav_ns
          root_href.content = lock.path
          lockroot.add_child(root_href)
          activelock.add_child(lockroot)

          doc.to_xml(indent: 2)
        end

        # Recursively rebind DAV: namespace nodes to the shared namespace definition.
        def rebind_dav_ns(node, dav_ns)
          return unless node.is_a?(Nokogiri::XML::Element)
          node.traverse do |n|
            next unless n.is_a?(Nokogiri::XML::Element)
            n.namespace = dav_ns if n.namespace&.href == "DAV:"
          end
        end
      end
    end
  end
end
