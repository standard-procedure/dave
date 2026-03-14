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
    def self.live_property(resource, clark_name)
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
        resource.collection? ? '<D:collection xmlns:D="DAV:"/>' : ""
      when "{DAV:}supportedlock"
        ""
      when "{DAV:}lockdiscovery"
        ""
      when "{DAV:}getcontentlanguage"
        nil
      end
    end

    # Returns a Hash of clark_name => xml_value_string for all applicable live
    # properties of the given resource. Properties that return nil are excluded.
    def self.live_properties(resource)
      LIVE_PROPS.each_with_object({}) do |clark_name, hash|
        value = live_property(resource, clark_name)
        hash[clark_name] = value unless value.nil?
      end
    end
  end
end
