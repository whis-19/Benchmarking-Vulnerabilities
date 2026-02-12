from flask import Flask, request, abort
import lxml.etree
from io import BytesIO

app = Flask(__name__)

# Define a maximum file size to prevent denial-of-service attacks.  Adjust as needed.
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB

# Define allowed XML tags and attributes.  This is crucial for security.
ALLOWED_TAGS = {'root', 'element', 'child', 'data'}  # Example: adjust to your needs
ALLOWED_ATTRIBUTES = {'id', 'name', 'value'}  # Example: adjust to your needs


def is_safe_xml(xml_string):
    """
    Checks if the XML string contains only allowed tags and attributes.
    This is a crucial security measure to prevent XML External Entity (XXE) attacks
    and other malicious XML payloads.

    Args:
        xml_string: The XML string to validate.

    Returns:
        True if the XML is safe, False otherwise.
    """
    try:
        parser = lxml.etree.XMLParser(recover=False)  # Disable recovery to catch errors
        tree = lxml.etree.parse(BytesIO(xml_string.encode('utf-8')), parser)

        for element in tree.iter():
            if element.tag not in ALLOWED_TAGS:
                print(f"Disallowed tag: {element.tag}")  # Log the disallowed tag
                return False
            for attribute in element.attrib:
                if attribute not in ALLOWED_ATTRIBUTES:
                    print(f"Disallowed attribute: {attribute}")  # Log the disallowed attribute
                    return False
        return True
    except lxml.etree.XMLSyntaxError as e:
        print(f"XML Syntax Error: {e}") # Log the syntax error
        return False
    except Exception as e:
        print(f"Error during XML parsing: {e}") # Log other errors
        return False


@app.post("/upload")
def upload():
    """
    Gets the XML source from the request, parses it, validates it, and returns it as a string.
    """
    if request.content_length > MAX_CONTENT_LENGTH:
        abort(413, "Request entity too large")  # Prevent large uploads

    try:
        xml_src = request.get_data(as_text=True)  # Get the raw data as text
    except Exception as e:
        print(f"Error reading request data: {e}")
        abort(400, "Invalid request data")

    if not xml_src:
        abort(400, "No XML data provided")

    if not is_safe_xml(xml_src):
        abort(400, "Unsafe XML content detected")

    try:
        parser = lxml.etree.XMLParser(recover=False) # Disable recovery for strict parsing
        tree = lxml.etree.parse(BytesIO(xml_src.encode('utf-8')), parser)
        xml_string = lxml.etree.tostring(tree, encoding='utf-8').decode('utf-8')
        return xml_string
    except lxml.etree.XMLSyntaxError as e:
        print(f"XML Syntax Error: {e}")
        abort(400, f"Invalid XML syntax: {e}")
    except Exception as e:
        print(f"Error parsing XML: {e}")
        abort(500, "Error processing XML")


if __name__ == "__main__":
    app.run(debug=True)

