from lxml import etree
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def transform_xml(xsl_filename="config.xsl"):
    '''
    Create an XML parser, parse the specified XSL file, and return an XSLT object.
    Includes error handling and secure path handling.

    Args:
        xsl_filename (str): The name of the XSL file to use (default: "config.xsl").
                             This should be a simple filename, not a path, for security.
    '''
    try:
        # Secure path handling:  Use os.path.join to construct the path safely.
        # This prevents path traversal vulnerabilities.
        script_dir = os.path.dirname(os.path.abspath(__file__))  # Get the directory of the script
        xsl_path = os.path.normpath(os.path.join(script_dir, 'resources', xsl_filename)) # Normalize path

        # Check if the file exists before attempting to parse it.
        if not os.path.exists(xsl_path):
            error_message = f"XSL file not found: {xsl_path}"
            logging.error(error_message)
            raise FileNotFoundError(error_message)

        # Create an XML parser.  Use lxml.etree.XMLParser for more control.
        # Disable DTD processing and entity expansion to prevent XXE vulnerabilities.
        # XXE (XML External Entity) attacks can allow attackers to read arbitrary files or execute code.
        parser = etree.XMLParser(dtd_validation=False, resolve_entities=False, no_network=True)

        # Parse the XSL file.
        try:
            xsl_tree = etree.parse(xsl_path, parser)
        except etree.XMLSyntaxError as e:
            logging.error(f"Error parsing XSL file: {e}")
            raise  # Re-raise the exception to be caught in the outer block

        # Determine XSLT version (if possible - often specified in the XSLT itself)
        xslt_version = None
        try:
            root = xsl_tree.getroot()
            if root.tag == "{http://www.w3.org/1999/XSL/Transform}stylesheet" or root.tag == "{http://www.w3.org/1999/XSL/Transform}transform":
                xslt_version = root.get("version")
                logging.info(f"XSLT version detected: {xslt_version}")
            else:
                logging.warning("Could not determine XSLT version from the stylesheet root element.")
        except Exception as e:
            logging.warning(f"Error determining XSLT version: {e}")


        # IMPORTANT:  Review the XSLT file carefully for potential XSLT injection vulnerabilities!
        # There is no perfect automated defense against malicious XSLT.  Treat the XSLT as executable code.
        # Consider restricting XSLT functionality (e.g., disabling document()) if possible.

        # Create an XSLT object.
        try:
            transform = etree.XSLT(xsl_tree)
        except etree.XSLTParseError as e:
            logging.error(f"Error creating XSLT transformation: {e}")
            raise # Re-raise to be caught in the outer block

        # Log XSLT file metadata (without logging the content)
        xsl_file_size = os.path.getsize(xsl_path)
        logging.info(f"XSLT file loaded: {xsl_filename}, size: {xsl_file_size} bytes")


        return transform

    except FileNotFoundError as e:
        logging.error(f"Error: {e}")
        return None  # Or raise the exception if appropriate for your application

    except etree.XMLSyntaxError as e:
        logging.error(f"Error parsing XSL file: {e}")
        return None  # Or raise the exception

    except Exception as e:
        logging.exception("An unexpected error occurred:")  # Log the full exception traceback
        return None  # Or raise the exception


def validate_xml(xml_tree, xsd_path):
    """
    Validates an XML tree against an XSD schema.

    Args:
        xml_tree: The lxml.etree._ElementTree object representing the XML document.
        xsd_path (str): The path to the XSD schema file.

    Returns:
        True if the XML is valid, False otherwise.  Logs errors if invalid.
    """
    try:
        xmlschema_doc = etree.parse(xsd_path)
        xmlschema = etree.XMLSchema(xmlschema_doc)
        xmlschema.assertValid(xml_tree)
        logging.info("XML validation successful.")
        return True
    except etree.XMLSchemaParseError as e:
        logging.error(f"Error parsing XSD schema: {e}")
        return False
    except etree.DocumentInvalid as e:
        logging.error(f"XML validation failed: {e}")
        return False
    except FileNotFoundError as e:
        logging.error(f"XSD file not found: {e}")
        return False
    except Exception as e:
        logging.exception("An unexpected error occurred during XML validation:")
        return False


if __name__ == '__main__':
    # Example usage (assuming you have a config.xsl file in a 'resources' directory):
    try:
        transform = transform_xml()

        if transform:
            # Example: Apply the transformation to a sample XML document
            xml_data = """
            <root>
                <element>Some data</element>
            </root>
            """
            xml_tree = etree.fromstring(xml_data)

            # TODO: Validate the XML input against a schema (XSD) if it comes from an untrusted source.
            # This helps prevent XSLT injection by ensuring the XSLT only operates on valid data.
            # Consider:
            #   - Schema validation (XSD) to enforce structure and data types.
            #   - Whitelisting allowed elements and attributes.
            #   - Data sanitization to prevent injection attacks.

            # Example of XML validation (assuming you have a schema.xsd file)
            xsd_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resources', 'schema.xsd')
            if os.path.exists(xsd_path):
                if validate_xml(xml_tree, xsd_path):
                    logging.info("XML is valid according to the schema.")
                else:
                    logging.warning("XML is NOT valid according to the schema.")
            else:
                logging.warning("Schema file (schema.xsd) not found. Skipping XML validation.")


            # Log XML metadata (without logging the content)
            xml_string = etree.tostring(xml_tree, encoding='utf8').decode('utf8')
            xml_size = len(xml_string)
            logging.info(f"XML data size: {xml_size} bytes")


            result_tree = transform(xml_tree)
            print(etree.tostring(result_tree, pretty_print=True).decode())
        else:
            print("Failed to create XSLT transformation.")

    except Exception as e:
        logging.exception("An error occurred in the main block:")
        print(f"An error occurred in the main block: {e}")

