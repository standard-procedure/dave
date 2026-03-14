require "spec_helper"
require "dave/xml"

RSpec.describe Dave::XML do
  describe "DAV_NS constant" do
    it "is the DAV: namespace URI" do
      expect(described_class::DAV_NS).to eq("DAV:")
    end
  end

  describe ".clark_to_ns" do
    it "parses DAV: namespace correctly" do
      ns, local = described_class.clark_to_ns("{DAV:}displayname")
      expect(ns).to eq("DAV:")
      expect(local).to eq("displayname")
    end

    it "parses custom namespace correctly" do
      ns, local = described_class.clark_to_ns("{http://example.com/ns/}custom")
      expect(ns).to eq("http://example.com/ns/")
      expect(local).to eq("custom")
    end

    it "returns a two-element array" do
      result = described_class.clark_to_ns("{DAV:}resourcetype")
      expect(result).to be_an(Array)
      expect(result.length).to eq(2)
    end
  end

  describe ".propstat" do
    let(:doc) { Nokogiri::XML::Document.new }

    it "returns a node with D:prop containing the property" do
      node = described_class.propstat({ "{DAV:}displayname" => "My File" }, 200)
      xml = node.to_xml
      expect(xml).to include("<D:prop")
      expect(xml).to include("displayname")
    end

    it "returns a node with D:status containing the HTTP status line" do
      node = described_class.propstat({ "{DAV:}displayname" => "My File" }, 200)
      xml = node.to_xml
      expect(xml).to include("<D:status>HTTP/1.1 200 OK</D:status>")
    end

    it "uses correct status message for 404" do
      node = described_class.propstat({ "{DAV:}getcontentlanguage" => "" }, 404)
      xml = node.to_xml
      expect(xml).to include("<D:status>HTTP/1.1 404 Not Found</D:status>")
    end

    it "returns a D:propstat element" do
      node = described_class.propstat({ "{DAV:}displayname" => "test" }, 200)
      expect(node.name).to eq("propstat")
    end
  end

  describe ".multistatus" do
    context "with one response and one propstat (200)" do
      let(:responses) do
        [
          {
            href: "/path/to/resource",
            propstats: [
              { props: { "{DAV:}displayname" => "My File" }, status: 200 }
            ]
          }
        ]
      end

      subject(:xml_string) { described_class.multistatus(responses) }

      it "starts with XML declaration" do
        expect(xml_string).to start_with("<?xml")
      end

      it "has D:multistatus root element with DAV: namespace" do
        expect(xml_string).to include('xmlns:D="DAV:"')
        expect(xml_string).to match(/<D:multistatus/)
      end

      it "contains D:response element" do
        expect(xml_string).to include("<D:response>")
      end

      it "contains D:href with the path" do
        expect(xml_string).to include("<D:href>/path/to/resource</D:href>")
      end

      it "contains D:propstat element" do
        expect(xml_string).to include("<D:propstat>")
      end

      it "contains D:prop with the displayname property" do
        expect(xml_string).to include("displayname")
        expect(xml_string).to include("My File")
      end

      it "contains D:status with HTTP/1.1 200 OK" do
        expect(xml_string).to include("<D:status>HTTP/1.1 200 OK</D:status>")
      end
    end

    context "with multiple propstats (200 and 404)" do
      let(:responses) do
        [
          {
            href: "/path/to/resource",
            propstats: [
              { props: { "{DAV:}displayname" => "My File" }, status: 200 },
              { props: { "{DAV:}getcontentlanguage" => "" }, status: 404 }
            ]
          }
        ]
      end

      subject(:xml_string) { described_class.multistatus(responses) }

      it "contains both D:propstat elements" do
        expect(xml_string.scan("<D:propstat>").length).to eq(2)
      end

      it "contains HTTP/1.1 200 OK status" do
        expect(xml_string).to include("<D:status>HTTP/1.1 200 OK</D:status>")
      end

      it "contains HTTP/1.1 404 Not Found status" do
        expect(xml_string).to include("<D:status>HTTP/1.1 404 Not Found</D:status>")
      end

      it "contains the 200 property value" do
        expect(xml_string).to include("My File")
      end
    end

    context "with multiple responses" do
      let(:responses) do
        [
          {
            href: "/resource1",
            propstats: [
              { props: { "{DAV:}displayname" => "Resource 1" }, status: 200 }
            ]
          },
          {
            href: "/resource2",
            propstats: [
              { props: { "{DAV:}displayname" => "Resource 2" }, status: 200 }
            ]
          }
        ]
      end

      subject(:xml_string) { described_class.multistatus(responses) }

      it "contains two D:response elements" do
        expect(xml_string.scan("<D:response>").length).to eq(2)
      end

      it "contains href for first resource" do
        expect(xml_string).to include("<D:href>/resource1</D:href>")
      end

      it "contains href for second resource" do
        expect(xml_string).to include("<D:href>/resource2</D:href>")
      end
    end

    context "property value handling" do
      context "when value is empty string" do
        let(:responses) do
          [
            {
              href: "/resource",
              propstats: [
                { props: { "{DAV:}displayname" => "" }, status: 200 }
              ]
            }
          ]
        end

        it "produces an empty element" do
          xml_string = described_class.multistatus(responses)
          doc = Nokogiri::XML(xml_string)
          prop = doc.at_xpath("//D:prop/D:displayname", "D" => "DAV:")
          expect(prop).not_to be_nil
          expect(prop.children).to be_empty
        end
      end

      context "when value is a text string" do
        let(:responses) do
          [
            {
              href: "/resource",
              propstats: [
                { props: { "{DAV:}displayname" => "My File" }, status: 200 }
              ]
            }
          ]
        end

        it "produces a text content element" do
          xml_string = described_class.multistatus(responses)
          doc = Nokogiri::XML(xml_string)
          prop = doc.at_xpath("//D:prop/D:displayname", "D" => "DAV:")
          expect(prop).not_to be_nil
          expect(prop.text).to eq("My File")
        end
      end

      context "when value is an XML fragment" do
        let(:responses) do
          [
            {
              href: "/resource",
              propstats: [
                { props: { "{DAV:}resourcetype" => "<D:collection/>" }, status: 200 }
              ]
            }
          ]
        end

        it "parses and inserts the XML fragment as child nodes" do
          xml_string = described_class.multistatus(responses)
          doc = Nokogiri::XML(xml_string)
          resourcetype = doc.at_xpath("//D:prop/D:resourcetype", "D" => "DAV:")
          expect(resourcetype).not_to be_nil
          collection = resourcetype.at_xpath("D:collection", "D" => "DAV:")
          expect(collection).not_to be_nil
        end
      end
    end
  end

  describe ".build_multistatus" do
    it "yields xml_builder and multistatus_node" do
      yielded_args = []
      described_class.build_multistatus { |xml, ms| yielded_args = [xml, ms] }
      expect(yielded_args.length).to eq(2)
    end

    it "returns a Nokogiri::XML::Document" do
      doc = described_class.build_multistatus { |xml, ms| }
      expect(doc).to be_a(Nokogiri::XML::Document)
    end

    it "has D:multistatus as root element" do
      doc = described_class.build_multistatus { |xml, ms| }
      expect(doc.root.name).to eq("multistatus")
    end

    it "root element has DAV: namespace" do
      doc = described_class.build_multistatus { |xml, ms| }
      expect(doc.root.namespace.href).to eq("DAV:")
    end

    it "allows caller to add D:response children via the block" do
      doc = described_class.build_multistatus do |xml, ms|
        response = ms.document.create_element("response")
        response.add_namespace_definition("D", "DAV:")
        ms.add_child(response)
      end
      expect(doc.root.children).not_to be_empty
    end
  end

  describe "STATUS_MESSAGES" do
    it "includes common WebDAV status codes" do
      messages = described_class::STATUS_MESSAGES
      expect(messages[200]).to eq("OK")
      expect(messages[201]).to eq("Created")
      expect(messages[204]).to eq("No Content")
      expect(messages[207]).to eq("Multi-Status")
      expect(messages[400]).to eq("Bad Request")
      expect(messages[403]).to eq("Forbidden")
      expect(messages[404]).to eq("Not Found")
      expect(messages[409]).to eq("Conflict")
      expect(messages[412]).to eq("Precondition Failed")
      expect(messages[422]).to eq("Unprocessable Entity")
      expect(messages[423]).to eq("Locked")
      expect(messages[424]).to eq("Failed Dependency")
      expect(messages[507]).to eq("Insufficient Storage")
    end

    it "is frozen" do
      expect(described_class::STATUS_MESSAGES).to be_frozen
    end
  end
end
