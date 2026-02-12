from lxml import etree
import logging
import os

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a default schema file path
DEFAULT_SCHEMA_PATH = "resources/config.xsd"

def get_root(config_file_path="resources/config.xml", schema_file_path=None):
    '''
    Create an XML parser, parse the specified XML file, validate against an optional schema, and return the root.
    '''
    try:
        # Create a parser that disables DTD processing and external entity loading
        parser = etree.XMLParser(
            dtd_validation=False,
            resolve_entities=False,
            load_dtd=False,  # Disable DTD loading entirely
        )

        # Parse the XML file
        tree = etree.parse(config_file_path, parser)
        root = tree.getroot()
        logging.info(f"Successfully parsed {config_file_path}")

        if schema_file_path:
            if not validate_xml(root, schema_file_path):
                logging.warning(f"XML validation against schema {schema_file_path} failed.")
                # Decide whether to return None or raise an exception based on validation failure.
                # Returning None might be appropriate if the application can function with potentially invalid data.
                # Raising an exception would enforce strict schema compliance.
                return None # Or raise an exception: raise ValueError("XML validation failed")

        return root
    except etree.XMLSyntaxError as e:
        logging.error(f"XML parsing error: {e}")
        return None  # Or raise the exception, depending on desired behavior
    except FileNotFoundError:
        logging.error(f"Error: {config_file_path} not found.")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception traceback
        return None


def validate_xml(root, xsd_file):
    """
    Validates an lxml Element (root) against an XSD schema file.
    """
    try:
        xmlschema_doc = etree.parse(xsd_file)
        xmlschema = etree.XMLSchema(xmlschema_doc)

        # Convert the root element back to an XML string for validation
        xml_string = etree.tostring(root).decode('utf-8')
        # Create an etree element from the string
        root_element = etree.fromstring(xml_string)

        xmlschema.assertValid(root_element)
        logging.info(f"XML validated successfully against schema: {xsd_file}")
        return True
    except etree.XMLSchemaError as e:
        logging.error(f"Schema validation error: {e}")
        return False
    except etree.XMLSyntaxError as e:
        logging.error(f"XML syntax error in schema file: {e}")
        return False
    except FileNotFoundError:
        logging.error(f"Schema file not found: {xsd_file}")
        return False
    except Exception as e:
        logging.exception(f"An unexpected error occurred during schema validation: {e}")
        return False


if __name__ == '__main__':
    # Example Usage:
    config_path = os.environ.get("CONFIG_FILE_PATH", "resources/config.xml") # Get path from environment variable, default to "resources/config.xml"
    schema_path = os.environ.get("SCHEMA_FILE_PATH", DEFAULT_SCHEMA_PATH) # Get schema path from environment variable, default to DEFAULT_SCHEMA_PATH

    root = get_root(config_path, schema_path)

    if root is not None:
        # Process the XML data
        print("XML parsed and (optionally) validated successfully.")
        # Example: Accessing a specific element
        # element = root.find(".//some_element")
        # if element is not None:
        #     print(f"Value of some_element: {element.text}")
    else:
        print("Failed to parse or validate XML.")

