require "time"

module Dave
  module Properties
    LIVE_PROPS = %w[
      {DAV:}displayname
      {DAV:}getcontentlength
      {DAV:}getcontenttype
      {DAV:}getetag
      {DAV:}getlastmodified
      {DAV:}creationdate
      {DAV:}resourcetype
      {DAV:}supportedlock
      {DAV:}lockdiscovery
      {DAV:}getcontentlanguage
    ].freeze

    # Returns true if the given Clark notation name is a known live property.
    def self.live?(clark_name)
      LIVE_PROPS.include?(clark_name)
    end

    # Returns the value of a single live property for the given resource.
    # Returns nil if the property does not apply to this resource.
    # Raises ArgumentError if clark_name is not a known live property — callers
    # must check live?(clark_name) before calling this method.
    def self.live_property(resource, clark_name, lock_manager: nil)
      raise ArgumentError, "#{clark_name.inspect} is not a live property" unless live?(clark_name)

      case clark_name
      when "{DAV:}displayname"
        # Last path segment, no trailing slash
        segments = resource.path.sub(%r{/\z}, "").split("/")
        segments.last || ""
      when "{DAV:}getcontentlength"
        return nil if resource.collection?
        resource.content_length&.to_s
      when "{DAV:}getcontenttype"
        return nil if resource.collection?
        resource.content_type
      when "{DAV:}getetag"
        resource.etag
      when "{DAV:}getlastmodified"
        resource.last_modified.httpdate
      when "{DAV:}creationdate"
        resource.created_at.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
      when "{DAV:}resourcetype"
        # The collection value is a raw XML fragment string. This is intentional:
        # Dave::XML handles XML fragment strings and performs DAV: namespace
        # rebinding when inserting them into a response document. This is the
        # agreed interface contract between Properties and Dave::XML.
        resource.collection? ? '<D:collection xmlns:D="DAV:"/>' : ""
      when "{DAV:}supportedlock"
        '<D:lockentry xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>' \
        '<D:lockentry xmlns:D="DAV:"><D:lockscope><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>'
      when "{DAV:}lockdiscovery"
        if lock_manager
          locks = lock_manager.locks_for(resource.path)
          build_lockdiscovery_xml(locks)
        else
          ""
        end
      when "{DAV:}getcontentlanguage"
        nil
      end
    end

    # Returns a Hash of clark_name => xml_value_string for all applicable live
    # properties of the given resource. Properties that return nil are excluded.
    def self.live_properties(resource, lock_manager: nil)
      LIVE_PROPS.each_with_object({}) do |clark_name, hash|
        value = live_property(resource, clark_name, lock_manager: lock_manager)
        hash[clark_name] = value unless value.nil?
      end
    end

    # Builds an XML fragment describing all active locks on a resource.
    def self.build_lockdiscovery_xml(locks)
      return "" if locks.empty?

      locks.map do |lock|
        depth_str   = lock.depth == :infinity ? "infinity" : "0"
        timeout_str = lock.timeout == :infinite ? "Infinite" : "Second-#{lock.timeout}"

        owner_xml = lock.owner ? "<D:owner>#{lock.owner}</D:owner>\n        " : ""

        <<~XML.strip
          <D:activelock xmlns:D="DAV:">
            <D:locktype><D:write/></D:locktype>
            <D:lockscope><D:#{lock.scope}/></D:lockscope>
            <D:depth>#{depth_str}</D:depth>
            #{owner_xml}<D:timeout>#{timeout_str}</D:timeout>
            <D:locktoken><D:href>#{lock.token}</D:href></D:locktoken>
            <D:lockroot><D:href>#{lock.path}</D:href></D:lockroot>
          </D:activelock>
        XML
      end.join
    end
  end
end
