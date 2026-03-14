require "nokogiri"

module Dave
  module XML
    DAV_NS = "DAV:".freeze

    STATUS_MESSAGES = {
      200 => "OK", 201 => "Created", 204 => "No Content",
      207 => "Multi-Status", 400 => "Bad Request", 403 => "Forbidden",
      404 => "Not Found", 409 => "Conflict", 412 => "Precondition Failed",
      422 => "Unprocessable Entity", 423 => "Locked",
      424 => "Failed Dependency", 507 => "Insufficient Storage"
    }.freeze

    # Parse a Clark notation name into [namespace, local_name].
    # e.g. "{DAV:}displayname" => ["DAV:", "displayname"]
    def self.clark_to_ns(clark_name)
      match = clark_name.match(/\A\{([^}]+)\}(.+)\z/)
      raise ArgumentError, "Invalid Clark notation: #{clark_name}" unless match
      [match[1], match[2]]
    end

    # Build a Nokogiri::XML::Document with a D:multistatus root element.
    # Yields (xml_doc, multistatus_node) to allow callers to add children.
    def self.build_multistatus
      doc = Nokogiri::XML::Document.new
      doc.encoding = "UTF-8"

      ms = doc.create_element("multistatus")
      ms.add_namespace_definition("D", DAV_NS)
      dav_ns = ms.namespace_definitions.find { |n| n.prefix == "D" }
      ms.namespace = dav_ns
      doc.root = ms

      yield doc, ms if block_given?

      doc
    end

    # Build a <D:propstat> node.
    # prop_hash: Hash of clark_name => xml_value_string
    # Returns a Nokogiri::XML::Node (standalone, in its own document).
    def self.propstat(prop_hash, status_code)
      doc = Nokogiri::XML::Document.new
      ms = doc.create_element("multistatus")
      ms.add_namespace_definition("D", DAV_NS)
      dav_ns = ms.namespace_definitions.find { |n| n.prefix == "D" }
      ms.namespace = dav_ns
      doc.root = ms

      build_propstat_node(doc, dav_ns, prop_hash, status_code)
    end

    # Build a full multistatus XML string from an array of response hashes.
    # Each response: { href: String, propstats: [{ props: Hash, status: Integer }] }
    def self.multistatus(responses)
      doc = build_multistatus do |xml_doc, ms|
        dav_ns = ms.namespace_definitions.find { |n| n.prefix == "D" }

        responses.each do |response|
          response_node = xml_doc.create_element("response")
          response_node.namespace = dav_ns
          ms.add_child(response_node)

          href_node = xml_doc.create_element("href")
          href_node.namespace = dav_ns
          href_node.content = response[:href]
          response_node.add_child(href_node)

          Array(response[:propstats]).each do |propstat_data|
            ps_node = build_propstat_node(xml_doc, dav_ns, propstat_data[:props], propstat_data[:status])
            response_node.add_child(ps_node)
          end
        end
      end

      doc.to_xml(indent: 2)
    end

    class << self
      private

      # Build a D:propstat element in the given document using the provided DAV namespace.
      def build_propstat_node(doc, dav_ns, prop_hash, status_code)
        propstat_node = doc.create_element("propstat")
        propstat_node.namespace = dav_ns

        prop_node = doc.create_element("prop")
        prop_node.namespace = dav_ns
        propstat_node.add_child(prop_node)

        prop_hash.each do |clark_name, value|
          ns_uri, local = clark_to_ns(clark_name)

          el = doc.create_element(local)

          if ns_uri == DAV_NS
            el.namespace = dav_ns
          else
            prefix = find_or_create_ns_prefix(prop_node, ns_uri)
            ns_def = prop_node.namespace_definitions.find { |n| n.href == ns_uri }
            el.namespace = ns_def
          end

          set_node_value(el, value, dav_ns, doc)
          prop_node.add_child(el)
        end

        status_msg = STATUS_MESSAGES[status_code] || "Unknown"
        status_node = doc.create_element("status")
        status_node.namespace = dav_ns
        status_node.content = "HTTP/1.1 #{status_code} #{status_msg}"
        propstat_node.add_child(status_node)

        propstat_node
      end

      # Find or register a namespace prefix on the given node, returning the prefix.
      def find_or_create_ns_prefix(node, ns_uri)
        existing = node.namespace_definitions.find { |n| n.href == ns_uri }
        return existing.prefix if existing

        prefix = "ns#{node.namespace_definitions.length}"
        node.add_namespace_definition(prefix, ns_uri)
        prefix
      end

      # Set the value of a property element.
      # - Empty string → no children (empty element)
      # - Plain text   → text content
      # - XML fragment → parse and insert as child nodes
      def set_node_value(el, value, dav_ns, doc)
        return if value.nil? || value.empty?

        if value.lstrip.start_with?("<")
          # Wrap in a dummy root with D namespace to parse the fragment
          wrapper_xml = "<wrapper xmlns:D=\"#{DAV_NS}\">#{value}</wrapper>"
          fragment_doc = Nokogiri::XML(wrapper_xml)
          fragment_doc.root.children.each do |child|
            imported = import_node(child, doc, dav_ns)
            el.add_child(imported)
          end
        else
          el.content = value
        end
      end

      # Import a node from another document into the target document,
      # rebinding DAV: namespace references to the provided dav_ns.
      def import_node(source_node, target_doc, dav_ns)
        # Duplicate the node, then move into target_doc via a temporary holder
        holder = target_doc.create_element("_holder")
        copy = source_node.dup
        holder.add_child(copy)
        imported = holder.children.first
        rebind_dav_namespace(imported, dav_ns)
        imported
      end

      # Recursively rebind DAV: namespace references on a node tree
      # so they point to the shared namespace definition.
      def rebind_dav_namespace(node, dav_ns)
        return unless node.is_a?(Nokogiri::XML::Element)
        node.traverse do |n|
          next unless n.is_a?(Nokogiri::XML::Element)
          n.namespace = dav_ns if n.namespace&.href == DAV_NS
        end
      end
    end
  end
end
