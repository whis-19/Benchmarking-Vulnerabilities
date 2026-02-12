from flask import Flask, request, abort
from defusedxml import ElementTree as SafeET
import logging
import re
from collections import deque

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define allowed XML elements and attributes (whitelisting)
ALLOWED_ELEMENTS = {"root", "data", "item"}  # Example: root, data, item
ALLOWED_ATTRIBUTES = {"id", "name", "value"}  # Example: id, name, value

# Maximum XML file size (in bytes) to prevent denial-of-service
MAX_XML_SIZE = 10240  # 10KB - Adjust as needed

# Maximum attribute value length
MAX_ATTRIBUTE_LENGTH = 256

# Regular expression for allowed attribute value characters (alphanumeric, underscore, hyphen)
ALLOWED_ATTRIBUTE_VALUE_CHARS = re.compile(r"^[a-zA-Z0-9_\-]+$")

# Maximum nesting depth to prevent denial-of-service
MAX_NESTING_DEPTH = 10

# Maximum number of elements to prevent DoS in xml_to_dict
MAX_ELEMENTS = 1000  # Adjust as needed

# Rate limiting configuration (example: 100 requests per minute)
RATE_LIMIT = 100
RATE_LIMIT_WINDOW = 60  # seconds
request_counts = {}  # Store request counts per IP address


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
            # Extract local name to handle namespaces
            tag_name = element.tag.split('}')[-1]

            if tag_name not in ALLOWED_ELEMENTS:
                logging.warning(f"Disallowed element: {element.tag} (local name: {tag_name})")
                return False

            for attribute, value in element.attrib.items():
                if attribute not in ALLOWED_ATTRIBUTES:
                    logging.warning(f"Disallowed attribute: {attribute}")
                    return False

                if len(value) > MAX_ATTRIBUTE_LENGTH:
                    logging.warning(f"Attribute '{attribute}' value exceeds maximum length.")
                    return False

                if not ALLOWED_ATTRIBUTE_VALUE_CHARS.match(value):
                    logging.warning(f"Attribute '{attribute}' value contains invalid characters.")
                    return False

        # Check for excessive nesting depth (DoS prevention) using iterative approach
        depth = 0
        max_depth = 0
        for element in tree.iter():
            depth = 0
            ancestor = element
            while ancestor is not None:
                depth += 1
                ancestor = next(iter(ancestor.iterancestors()), None)  # Get the next ancestor or None
            max_depth = max(max_depth, depth)
            if max_depth > MAX_NESTING_DEPTH:
                logging.warning(f"Excessive nesting depth: {max_depth}")
                return False

        return True

    except SafeET.ParseError as e:
        logging.error(f"XML Parse Error: {e}")
        return False
    except Exception as e:
        logging.exception("Unexpected error during XML validation")
        return False


def xml_to_dict(element, depth=0, element_count=0):
    """
    Converts an XML element to a Python dictionary.  This is just an example;
    adapt it to your specific XML structure.  Handles attributes and mixed content.
    Includes depth limiting and element count limiting to prevent DoS.

    Args:
        element: The XML element to convert.
        depth: Current nesting depth (for DoS protection).
        element_count: Current element count (for DoS protection).

    Returns:
        A dictionary representation of the XML element.
    """

    if depth > MAX_NESTING_DEPTH:
        logging.warning("Exceeded maximum nesting depth in xml_to_dict")
        raise ValueError("Exceeded maximum nesting depth")

    if element_count > MAX_ELEMENTS:
        logging.warning("Exceeded maximum number of elements in xml_to_dict")
        raise ValueError("Exceeded maximum number of elements")

    data = {}
    element_count += 1  # Increment element count

    if element.attrib:
        data["attributes"] = element.attrib

    if element.text and element.text.strip():
        data["text"] = element.text.strip()

    for child in element:
        # Extract local name to handle namespaces
        child_tag = child.tag.split('}')[-1]
        try:
            child_data = xml_to_dict(child, depth + 1, element_count)
        except ValueError as e:
            raise e  # Re-raise the exception to stop processing

        if child_tag in data:
            if not isinstance(data[child_tag], list):
                data[child_tag] = [data[child_tag]]
            data[child_tag].append(child_data)
        else:
            data[child_tag] = child_data

    return data


def rate_limit_exceeded(ip_address):
    """
    Checks if the rate limit has been exceeded for a given IP address.

    Args:
        ip_address: The IP address to check.

    Returns:
        True if the rate limit has been exceeded, False otherwise.
    """
    import time
    now = time.time()
    if ip_address not in request_counts:
        request_counts[ip_address] = deque()

    # Remove requests older than the rate limit window
    while request_counts[ip_address] and request_counts[ip_address][0] < now - RATE_LIMIT_WINDOW:
        request_counts[ip_address].popleft()

    if len(request_counts[ip_address]) >= RATE_LIMIT:
        return True

    request_counts[ip_address].append(now)
    return False


@app.post("/upload")
def upload():
    """
    Reads the XML from the incoming request, parses it safely, and returns the parsed XML.
    """
    ip_address = request.remote_addr  # Get the client's IP address

    if rate_limit_exceeded(ip_address):
        logging.warning(f"Rate limit exceeded for IP: {ip_address}")
        abort(429, "Too Many Requests")  # HTTP 429: Too Many Requests

    if request.content_length > MAX_XML_SIZE:
        logging.warning(f"Request size exceeds maximum allowed size: {MAX_XML_SIZE} bytes")
        abort(413, "Request entity too large")  # HTTP 413: Request Entity Too Large

    if request.content_type != 'application/xml' and request.content_type != 'text/xml':
        logging.warning(f"Invalid Content-Type: {request.content_type}")
        return "Invalid Content-Type.  Must be application/xml or text/xml", 400  # HTTP 400: Bad Request

    try:
        xml_data = request.data.decode("utf-8")  # Decode the request data

        if not xml_data:
            logging.warning("Empty XML data received")
            return "No XML data provided", 400  # HTTP 400: Bad Request

        if not is_safe_xml(xml_data):
            logging.warning("Unsafe XML detected")
            return "Unsafe XML data", 400  # HTTP 400: Bad Request

        # Parse the XML using defusedxml
        root = SafeET.fromstring(xml_data)

        # Process the parsed XML (example: convert to a dictionary)
        try:
            xml_dict = xml_to_dict(root)
        except ValueError as e:
            logging.warning(f"Error during xml_to_dict: {e}")
            return str(e), 400  # Return the error message to the client

        return xml_dict, 200  # HTTP 200: OK

    except UnicodeDecodeError:
        logging.warning("Invalid XML encoding")
        return "Invalid XML encoding", 400  # HTTP 400: Bad Request
    except Exception as e:
        logging.exception("Error processing XML")
        return "Error processing XML", 500  # HTTP 500: Internal Server Error


if __name__ == "__main__":
    # DO NOT USE debug=True IN PRODUCTION
    app.run(debug=False)

