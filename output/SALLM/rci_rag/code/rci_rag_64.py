import lxml.etree
from defusedxml.lxml import fromstring, tostring
from flask import Flask, request, abort
import os
import logging
import sys

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Schema Location (configurable via environment variable)
SCHEMA_PATH = os.environ.get("SCHEMA_PATH", "schema.xsd")

# Load the XML schema (XSD)
try:
    xml_schema = lxml.etree.XMLSchema(lxml.etree.parse(SCHEMA_PATH))
    logger.info(f"Successfully loaded schema from {SCHEMA_PATH}")
except lxml.etree.XMLSyntaxError as e:
    logger.error(f"Error loading schema from {SCHEMA_PATH}: {e}")
    print(f"Error loading schema: {e}")
    print("Application cannot start without a valid schema. Exiting.")
    sys.exit(1)


@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    '''
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string.
    :return: The XML as a string.
    '''

    # Content-Type Validation
    if request.headers['Content-Type'] != 'application/xml':
        logger.warning(f"Invalid Content-Type: {request.headers['Content-Type']}")
        return "Error: Content-Type must be application/xml", 400

    # Request Size Limit (e.g., 1MB)
    max_content_length = 1024 * 1024
    if request.content_length is None or request.content_length > max_content_length:
        logger.warning(f"Request size exceeds limit or content length is missing: {request.content_length}")
        return "Error: Request size exceeds the limit", 413  # Request Entity Too Large

    try:
        xml_src = request.data.decode('utf-8')  # Get XML from request body
    except UnicodeDecodeError as e:
        logger.error(f"UnicodeDecodeError: {e}")
        return "Error: Invalid UTF-8 encoding in XML data", 400

    if not xml_src:
        logger.warning("Empty XML data received")
        return "Error: XML data is missing in the request body", 400

    try:
        # Use defusedxml.lxml.fromstring to parse the XML safely
        xml_doc = fromstring(xml_src.encode('utf-8')) # Encode to bytes for defusedxml

        # Validate against the schema
        try:
            xml_schema.assertValid(xml_doc)
        except lxml.etree.DocumentInvalid as e:
            logger.warning(f"XML does not conform to schema: {e}")
            return f"Error: XML does not conform to schema", 400  # Mask the specific error

        # Convert the XML back to a string for the response
        xml_string = tostring(xml_doc, encoding='utf-8').decode('utf-8') # Explicit encoding

        return xml_string, 200

    except lxml.etree.XMLSyntaxError as e:
        logger.warning(f"Invalid XML syntax: {e}")
        return "Error: Invalid XML syntax", 400 # Mask the specific error
    except Exception as e:
        logger.exception("Unexpected error:")  # Logs the full traceback
        return "Error: An unexpected error occurred", 500 # Generic error for the client


if __name__ == '__main__':
    app.run(debug=True)

