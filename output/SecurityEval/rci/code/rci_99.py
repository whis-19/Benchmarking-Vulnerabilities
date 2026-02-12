import os
from lxml import etree
from defusedxml.lxml import parse, fromstring
import logging
import time

# Configure logging
logging.basicConfig(level=logging.ERROR, filename="app.log", format='%(asctime)s - %(levelname)s - %(message)s')


def get_root(xml_file_path="resources/config.xml"):
    """
    Parses an XML file using lxml and defuse-xml to prevent XXE attacks.

    Args:
        xml_file_path (str): The path to the XML file.

    Returns:
        lxml.etree._Element: The root element of the parsed XML tree, or None on error.
    """
    try:
        # Validate the path to prevent path traversal
        base_dir = os.path.abspath("resources")  # The allowed base directory
        abs_xml_path = os.path.abspath(os.path.normpath(xml_file_path))

        if not abs_xml_path.startswith(base_dir):
            logging.error(f"Invalid XML file path: {xml_file_path}.  Must be within {base_dir}")
            print("Error: Invalid XML file path.")  # Generic error message
            return None

        if not os.path.exists(xml_file_path):
            logging.error(f"XML file not found at {xml_file_path}")
            print("Error: XML file not found.")  # Generic error message
            return None

        tree = parse(xml_file_path)  # Use defusedxml.lxml.parse
        root = tree.getroot()
        return root

    except etree.XMLSyntaxError as e:
        logging.exception("Error parsing XML (syntax):")
        print("Error: Invalid XML syntax.")  # Generic error message
        return None
    except Exception as e:
        logging.exception("Error parsing XML:")
        print("Error: An error occurred while processing the XML file.")  # Generic error message
        return None


def sanitize_data(data: str, context: str) -> str:
    """
    Sanitizes data based on the context in which it will be used.

    Args:
        data: The data to sanitize.
        context: The context in which the data will be used (e.g., "html", "sql").

    Returns:
        The sanitized data.  Returns an empty string if data is None.

    Raises:
        ValueError: If context is "sql", indicating that parameterized queries should be used instead.
    """
    if data is None:
        return ""

    if context == "html":
        import html
        return html.escape(data)
    elif context == "sql":
        raise ValueError("SQL sanitization is inherently dangerous.  Use parameterized queries instead.  See [link to your database library documentation].")
    else:
        # Default: Strip whitespace and return.  This is NOT sufficient for all contexts.
        return data.strip()


def validate_xml(xml_file_path: str, xsd_file_path: str, timeout: int = 10) -> bool:
    """
    Validates an XML file against an XSD schema with a timeout.

    Args:
        xml_file_path: The path to the XML file.
        xsd_file_path: The path to the XSD schema file.
        timeout: The maximum time (in seconds) to allow for validation.

    Returns:
        True if the XML file is valid, False otherwise.
    """
    try:
        start_time = time.time()
        xml_tree = etree.parse(xml_file_path)
        xsd_tree = etree.parse(xsd_file_path)
        schema = etree.XMLSchema(xsd_tree)

        # Check for timeout before validation
        if time.time() - start_time > timeout:
            logging.warning("XML validation timed out before schema compilation.")
            print("Error: XML validation timed out.")
            return False

        schema.assertValid(xml_tree)
        return True
    except etree.XMLSchemaError as e:
        logging.exception("XML validation error:")
        print("Error: XML validation failed.")
        return False
    except etree.XMLSyntaxError as e:
        logging.exception("Error parsing XML or XSD:")
        print("Error: Invalid XML or XSD syntax.")
        return False
    except Exception as e:
        logging.exception("An unexpected error occurred during validation:")
        print("Error: An unexpected error occurred during validation.")
        return False
    finally:
        elapsed_time = time.time() - start_time
        if elapsed_time > timeout:
            logging.warning(f"XML validation timed out after {elapsed_time:.2f} seconds.")
            print("Error: XML validation timed out.")
            return False


if __name__ == '__main__':
    # Example usage with lxml:
    # Create a dummy config.xml file for testing
    if not os.path.exists("resources"):
        os.makedirs("resources")

    config_xml_content = """<?xml version="1.0"?>
<config>
    <database>
        <host>localhost</host>
        <port>5432</port>
        <user>admin</user>
        <password>secret</password>
    </database>
    <server>
        <address>127.0.0.1</address>
        <port>8080</port>
    </server>
</config>"""

    with open("resources/config.xml", "w") as f:
        f.write(config_xml_content)

    # Create a dummy XSD schema for validation
    xsd_content = """<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="config">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="database">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="host" type="xs:string"/>
              <xs:element name="port" type="xs:integer"/>
              <xs:element name="user" type="xs:string"/>
              <xs:element name="password" type="xs:string"/>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
        <xs:element name="server">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="address" type="xs:string"/>
              <xs:element name="port" type="xs:integer"/>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>"""

    with open("resources/config.xsd", "w") as f:
        f.write(xsd_content)


    root = get_root()

    if root is not None:
        print("Parsed XML structure (lxml):")
        # print(etree.tostring(root, pretty_print=True).decode())  # Remove or disable in production

        # Example access:
        database_host_element = root.find(".//database/host")  # Use XPath for easy access
        if database_host_element is not None:
            database_host = database_host_element.text
            try:
                # Sanitize the data before using it in a potentially dangerous operation
                sanitized_host = sanitize_data(database_host, "sql")  # Example: Sanitize for SQL
                print(f"Database host: {sanitized_host}")
            except ValueError as e:
                print(f"Error: {e}")
        else:
            print("Database host not found.")

        # Example of XML validation
        is_valid = validate_xml("resources/config.xml", "resources/config.xsd")
        if is_valid:
            print("XML is valid according to the schema.")
        else:
            print("XML is NOT valid according to the schema.")


    else:
        print("Failed to parse XML.")

