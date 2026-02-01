from defusedxml.ElementTree import fromstring, parse
import logging
from lxml import etree  # Import lxml

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def validate_xml(xml_string, xsd_file):
    """
    Validates the XML string against an XSD schema.
    """
    try:
        xml_doc = etree.fromstring(xml_string, parser=etree.XMLParser(resolve_entities=False)) # Disable entity resolution!
        xsd_doc = etree.parse(xsd_file)
        xsd = etree.XMLSchema(xsd_doc)
        xsd.assertValid(xml_doc)
        return True
    except etree.XMLSyntaxError as e:
        logging.error(f"XML Syntax Error: {e}")
        return False
    except etree.XMLSchemaError as e:
        logging.error(f"XSD Schema Error: {e}")
        return False
    except etree.DocumentInvalid as e:
        logging.error(f"XML Validation Error: {e}")
        return False
    except FileNotFoundError:
        logging.error(f"XSD file not found: {xsd_file}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error during validation: {e}")
        return False


def parse_xml(xml_string, xsd_file=None):
    '''
    Parse xml_string and return the root element of the XML document
    using defusedxml to prevent XML attacks.  Optionally validates against an XSD.
    '''
    if xsd_file:
        if not validate_xml(xml_string, xsd_file):
            return None  # Validation failed, don't parse

    try:
        root = fromstring(xml_string)
        return root
    except Exception as e:
        logging.error(f"Error parsing XML string: {e}")  # Log the error
        return None

def parse_xml_from_file(xml_file, xsd_file=None):
    '''
    Parse xml_file and return the root element of the XML document
    using defusedxml to prevent XML attacks.  Optionally validates against an XSD.
    '''
    try:
        with open(xml_file, 'r') as f:
            xml_string = f.read()

        if xsd_file:
            if not validate_xml(xml_string, xsd_file):
                return None  # Validation failed, don't parse

        tree = parse(xml_file)
        root = tree.getroot()
        return root
    except FileNotFoundError:
        logging.error(f"XML file not found: {xml_file}")
        return None
    except Exception as e:
        logging.error(f"Error parsing XML file {xml_file}: {e}")  # Log the error
        return None


if __name__ == '__main__':
    # Example usage:

    # Example 1: Parsing from a string with validation
    xml_data = "<root><element>Hello, World!</element></root>"
    # Create a simple XSD file (example.xsd)
    # <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
    #   <xs:element name="root">
    #     <xs:complexType>
    #       <xs:sequence>
    #         <xs:element name="element" type="xs:string"/>
    #       </xs:sequence>
    #     </xs:complexType>
    #   </xs:element>
    # </xs:schema>

    try:
        with open("example.xsd", "w") as f:
            f.write("""<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="root">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="element" type="xs:string"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>""")

        root = parse_xml(xml_data, "example.xsd")
        if root is not None:
            print(f"Root tag: {root.tag}")
            for element in root:
                print(f"Element tag: {element.tag}, text: {element.text}")
    except Exception as e:
        logging.error(f"Error during validation example setup or parsing: {e}")

    # Example 2: Parsing from a file with validation
    try:
        with open("example.xml", "w") as f:
            f.write("<root><element>Hello from file!</element></root>")

        root = parse_xml_from_file("example.xml", "example.xsd")
        if root is not None:
            print(f"Root tag (from file): {root.tag}")
            for element in root:
                print(f"Element tag (from file): {element.tag}, text: {element.text}")
    except Exception as e:
        logging.error(f"Error during file example setup or parsing: {e}")


    # Example 3:  Illustrating vulnerability prevention (attempting to use an external entity - this will be blocked by defusedxml)
    # Create a file named "external.txt" with some content, e.g., "External content"
    # Then, uncomment the following lines to see defusedxml in action.  It will raise an exception.
    # xml_data_evil = """<?xml version="1.0"?>
    # <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    # <root><element>&xxe;</element></root>""" # Or "file://external.txt"
    # try:
    #     root = parse_xml(xml_data_evil)
    #     if root is not None:
    #         print(f"Root tag: {root.tag}")
    #         for element in root:
    #             print(f"Element tag: {element.tag}, text: {element.text}")
    # except Exception as e:
    #     print(f"XXE Prevention Demo: Error parsing XML (as expected): {e}")
    #     logging.exception("XXE Prevention Demo: Error parsing XML (as expected)") # Log the full exception traceback

