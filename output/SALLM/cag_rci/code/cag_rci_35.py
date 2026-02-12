from lxml import etree
import os
import re
import threading

# Define the maximum allowed XML file size (in bytes)
MAX_XML_SIZE = 1024 * 1024  # 1 MB
# Define the timeout for XML parsing (in seconds)
XML_PARSING_TIMEOUT = 5

def sanitize_filename(filename):
    """Sanitizes a filename to prevent path traversal and other attacks."""
    # Whitelist of allowed characters
    allowed_chars = r"[a-zA-Z0-9_\-.]"
    # Remove any directory components
    filename = os.path.basename(filename)
    # Remove any characters not in the whitelist
    filename = re.sub(rf"[^{allowed_chars}]", "", filename)
    # Normalize the path
    filename = os.path.normpath(filename)
    return filename

def validate_schema(schema_file):
    """Validates an XML schema against the W3C XML Schema schema."""
    try:
        # Load the W3C XML Schema schema
        schema_doc = etree.parse("path/to/XMLSchema.xsd")  # Replace with the actual path
        schema = etree.XMLSchema(schema_doc)

        # Parse the schema to be validated
        xmlschema_doc = etree.parse(schema_file)

        # Validate the schema
        schema.assertValid(xmlschema_doc)
        print(f"Schema '{schema_file}' is valid according to the W3C XML Schema.")
        return True
    except etree.XMLSyntaxError as e:
        print(f"Schema Syntax Error in '{schema_file}': {e}")
        return False
    except etree.XMLSchemaError as e:
        print(f"Schema Validation Error in '{schema_file}': {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred while validating the schema: {e}")
        return False

def parse_xml_with_timeout(filename, parser, timeout_seconds):
    """Parses an XML file with a timeout."""
    result = {"doc": None, "error": None}
    timer = None

    def parse_task():
        try:
            result["doc"] = etree.parse(filename, parser=parser)
        except Exception as e:
            result["error"] = e
        finally:
            if timer and timer.is_alive():
                timer.cancel()  # Cancel the timer if parsing completes

    parse_thread = threading.Thread(target=parse_task)
    parse_thread.start()

    def timeout_handler():
        result["error"] = TimeoutError(f"Parsing '{filename}' timed out after {timeout_seconds} seconds.")
        # Attempt to stop the parsing thread (this might not always work reliably)
        # You might need to use more aggressive methods like os.kill() in extreme cases,
        # but be very careful with that.
        parse_thread.join(timeout=0.1) # Give the thread a chance to exit
        if parse_thread.is_alive():
            print("Warning: Could not cleanly terminate parsing thread.")


    timer = threading.Timer(timeout_seconds, timeout_handler)
    timer.start()

    parse_thread.join()  # Wait for the parsing thread to finish

    if result["error"]:
        raise result["error"]  # Re-raise the exception
    return result["doc"]


def validate_xml(schema_file, xml_file):
    """Validates an XML file against a schema, with security mitigations."""

    # 1. Check file sizes *before* parsing
    if os.path.getsize(schema_file) > MAX_XML_SIZE or os.path.getsize(xml_file) > MAX_XML_SIZE:
        raise ValueError("XML file exceeds maximum allowed size.")

    # 2. Sanitize filenames
    schema_file = sanitize_filename(schema_file)
    xml_file = sanitize_filename(xml_file)

    # 3. Validate the schema itself
    if not validate_schema(schema_file):
        raise ValueError("Invalid XML schema.")

    # 4. Disable external entity resolution
    parser = etree.XMLParser(resolve_entities=False)

    try:
        # 5. Parse the schema
        xmlschema_doc = etree.parse(schema_file, parser=parser)
        xmlschema = etree.XMLSchema(xmlschema_doc)

        # 6. Parse the XML file with a timeout
        xml_doc = parse_xml_with_timeout(xml_file, parser, XML_PARSING_TIMEOUT)

        # 7. Validate the XML against the schema
        xmlschema.assertValid(xml_doc)
        print("XML is valid.")

    except etree.XMLSyntaxError as e:
        print(f"XML Syntax Error: {e}")
    except etree.XMLSchemaError as e:
        print(f"Schema Validation Error: {e}")
    except ValueError as e:
        print(f"Value Error: {e}") # File size error or invalid schema
    except TimeoutError as e:
        print(f"Timeout Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


# Example usage (assuming schema_file and xml_file are properly defined and sanitized)
schema_file = "my_schema.xsd"
xml_file = "my_xml_file.xml"

validate_xml(schema_file, xml_file)

