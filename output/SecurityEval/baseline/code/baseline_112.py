from flask import Flask, request, abort
import xml.etree.ElementTree as ET
from defusedxml import ElementTree as SafeET  # Import defusedxml for safe parsing

app = Flask(__name__)

# Define allowed XML elements and attributes (whitelisting)
ALLOWED_ELEMENTS = {"root", "data", "item"}  # Example: root, data, item
ALLOWED_ATTRIBUTES = {"id", "name", "value"}  # Example: id, name, value

# Maximum XML file size (in bytes) to prevent denial-of-service
MAX_XML_SIZE = 10240  # 10KB - Adjust as needed

def is_safe_xml(xml_string):
    """
    Validates XML string against a whitelist of allowed elements and attributes.
    Also checks for potentially dangerous constructs.

    Args:
        xml_string: The XML string to validate.

    Returns:
        True if the XML is safe, False otherwise.
    """
    try:
        tree = SafeET.fromstring(xml_string)  # Use defusedxml for parsing

        for element in tree.iter():
            if element.tag not in ALLOWED_ELEMENTS:
                print(f"Disallowed element: {element.tag}")
                return False

            for attribute in element.attrib:
                if attribute not in ALLOWED_ATTRIBUTES:
                    print(f"Disallowed attribute: {attribute}")
                    return False

        # Check for external entity references (XXE) - already handled by defusedxml, but good to be explicit
        # defusedxml prevents external entity resolution by default.  No need to explicitly check for it.

        # Check for excessive nesting depth (to prevent denial-of-service)
        depth = 0
        for element in tree.iter():
            current_depth = 0
            parent = element.getparent()
            while parent is not None:
                current_depth += 1
                parent = parent.getparent()
            depth = max(depth, current_depth)

        if depth > 10:  # Adjust maximum depth as needed
            print("Excessive nesting depth detected.")
            return False

        return True

    except SafeET.ParseError as e:
        print(f"XML parsing error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error during XML validation: {e}")
        return False


@app.post("/upload")
def upload():
    """
    Reads the XML from the incoming request, parses it safely, and returns the parsed XML.
    """
    if request.content_length > MAX_XML_SIZE:
        abort(413, "Request entity too large. XML size exceeds the limit.")

    try:
        xml_data = request.data.decode('utf-8')  # Decode the request data

        if not xml_data:
            return "No XML data provided", 400

        if not is_safe_xml(xml_data):
            return "Unsafe XML content detected", 400

        # Parse the XML using defusedxml
        root = SafeET.fromstring(xml_data)

        # Process the parsed XML (example: convert to a dictionary)
        #  Important:  Handle the parsed XML data carefully.  Avoid using it directly in system calls or other potentially dangerous operations.
        parsed_data = xml_to_dict(root)  # Use a helper function to convert to a dictionary

        return parsed_data, 200  # Return the parsed data (e.g., as JSON)

    except UnicodeDecodeError:
        return "Invalid XML encoding.  Please use UTF-8.", 400
    except Exception as e:
        print(f"Error processing XML: {e}")
        return "Error processing XML", 500


def xml_to_dict(element):
    """
    Helper function to convert an XML element to a dictionary.
    This is a basic example and can be extended to handle more complex XML structures.
    """
    data = {}
    for child in element:
        if len(child):  # If the child has children, recursively process it
            data[child.tag] = xml_to_dict(child)
        else:
            data[child.tag] = child.text
    return data


if __name__ == "__main__":
    app.run(debug=True)

