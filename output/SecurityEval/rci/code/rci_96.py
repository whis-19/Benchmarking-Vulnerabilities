from lxml import etree
import os
import logging

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

class InvalidXmlError(Exception):
    pass

class SchemaValidationError(Exception):
    pass


def get_root(config_path):
    '''
    Create an XML parser, parse the XML file at config_path and return the root.
    Raises InvalidXmlError if an error occurs.
    '''
    try:
        # Check if the file exists before attempting to parse it.
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}")

        # Use a secure XML parser to prevent XML External Entity (XXE) attacks and DoS attacks.
        parser = etree.XMLParser(resolve_entities=False, no_network=True, remove_blank_text=True, remove_comments=True, remove_pis=True)

        # Parse the XML file.  Handle potential parsing errors gracefully.
        tree = etree.parse(config_path, parser)
        root = tree.getroot()
        return root

    except FileNotFoundError as e:
        logging.error(f"Config file not found: {e}")
        raise  # Re-raise the exception

    except etree.XMLSyntaxError as e:
        logging.error(f"Error parsing XML: {e}")
        raise InvalidXmlError(f"XML syntax error: {e}") from e

    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Include traceback
        raise InvalidXmlError(f"Unexpected error: {e}") from e


def validate_xml(xml_file, xsd_file):
    """
    Validates an XML file against an XSD schema.

    Args:
        xml_file (str): Path to the XML file.
        xsd_file (str): Path to the XSD file.

    Returns:
        bool: True if the XML is valid.
    Raises:
        SchemaValidationError: If the XML is invalid or an error occurs during validation.
        InvalidXmlError: If there is an XML syntax error.
    """
    try:
        xml_doc = etree.parse(xml_file)
        xsd_doc = etree.parse(xsd_file)
        xmlschema = etree.XMLSchema(xsd_doc)
        xmlschema.assertValid(xml_doc)
        return True
    except etree.XMLSchemaError as e:
        logging.error(f"XML validation error: {e}")
        raise SchemaValidationError(f"XML validation error: {e}") from e
    except etree.XMLSyntaxError as e:
        logging.error(f"XML syntax error: {e}")
        raise InvalidXmlError(f"XML syntax error: {e}") from e
    except Exception as e:
        logging.exception(f"An unexpected error occurred during validation: {e}")
        raise SchemaValidationError(f"Unexpected error during validation: {e}") from e


if __name__ == '__main__':
    # Example usage:  Create a dummy config.xml for testing.
    # This part is only executed when the script is run directly.
    if not os.path.exists("resources"):
        os.makedirs("resources")

    config_file_path = os.path.join("resources", "config.xml")
    if not os.path.exists(config_file_path):
        with open(config_file_path, "w") as f:
            f.write("<root><setting1>value1</setting1><setting2>value2</setting2></root>")

    # Example XSD validation (optional)
    xsd_file_path = os.path.join("resources", "config.xsd")
    if not os.path.exists(xsd_file_path):
        with open(xsd_file_path, "w") as f:
            f.write('''<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
              <xs:element name="root">
                <xs:complexType>
                  <xs:sequence>
                    <xs:element name="setting1" type="xs:string"/>
                    <xs:element name="setting2" type="xs:string"/>
                  </xs:sequence>
                </xs:complexType>
              </xs:element>
            </xs:schema>''')

    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, 'resources', 'config.xml')

    try:
        root = get_root(config_path)
        if root is not None:
            print("Root element:", root.tag)
            for child in root:
                print(f"  {child.tag}: {child.text}")

            # Validate the XML (optional)
            if os.path.exists(xsd_file_path):
                try:
                    validate_xml(config_file_path, xsd_file_path)
                    print("XML is valid according to the schema.")
                except (SchemaValidationError, InvalidXmlError) as e:
                    print(f"XML is NOT valid according to the schema: {e}")
            else:
                print("XSD file not found. Skipping validation.")


        else:
            print("Failed to load XML configuration.")
    except (InvalidXmlError, FileNotFoundError) as e:
        print(f"Error processing XML: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

