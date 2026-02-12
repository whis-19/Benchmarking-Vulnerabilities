from flask import Flask, request, Response
import lxml.etree
from io import BytesIO
import logging
import re  # For sanitization
from defusedxml.lxml import fromstring, tostring  # For safer XML processing

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Maximum XML size (in bytes) to prevent DoS
MAX_XML_SIZE = 1024 * 1024  # 1MB

# Maximum XML depth to prevent DoS
MAX_XML_DEPTH = 20

# Allowed Content-Type
ALLOWED_CONTENT_TYPES = ['application/x-www-form-urlencoded', 'application/xml', 'text/xml']

# Define a schema (replace with your actual schema file)
# SCHEMA_FILE = 'schema.xsd'  # Uncomment and set if you have a schema

# Function to sanitize XML content (example)
def sanitize_xml(xml_string):
    """
    Removes potentially dangerous attributes like onload, onclick, etc.
    This is a basic example and should be adapted to your specific needs.
    """
    # Remove attributes like onload, onclick, etc.
    xml_string = re.sub(r'\s(?:onload|onclick|on\w+)=["\'][^"\']*["\']', '', xml_string, flags=re.IGNORECASE)
    # Remove javascript: URLs
    xml_string = re.sub(r'javascript:', '', xml_string, flags=re.IGNORECASE)
    return xml_string


# Function to calculate XML depth (requires traversal)
def get_xml_depth(element, depth=0):
    max_depth = depth
    for child in element:
        max_depth = max(max_depth, get_xml_depth(child, depth + 1))
    return max_depth


@app.post("/parse_xml")
def parse_xml():
    '''
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string.
    :return: The XML as a string.
    '''
    try:
        # Content-Type Validation
        content_type = request.headers.get('Content-Type')
        if content_type not in ALLOWED_CONTENT_TYPES:
            logger.warning(f"Invalid Content-Type: {content_type}")
            return Response("Invalid Content-Type.  Must be application/x-www-form-urlencoded, application/xml, or text/xml.", status=400, mimetype='text/plain')

        xml_src = request.form.get('xml_src') if content_type == 'application/x-www-form-urlencoded' else request.data.decode('utf-8')

        if not xml_src:
            logger.warning("Missing 'xml_src' parameter in request.")
            return Response("Missing 'xml_src' parameter.", status=400, mimetype='text/plain')

        # Check XML size to prevent DoS
        xml_bytes = xml_src.encode('utf-8')
        if len(xml_bytes) > MAX_XML_SIZE:
            logger.warning(f"XML size exceeds maximum allowed size ({MAX_XML_SIZE} bytes).  Request size: {len(xml_bytes)} bytes.")
            return Response("XML size exceeds the maximum allowed size.", status=400, mimetype='text/plain')

        # Sanitize XML content
        xml_src = sanitize_xml(xml_src)

        # Use BytesIO to handle potential encoding issues and prevent XXE
        xml_file = BytesIO(xml_bytes)

        try:
            # Use defusedxml for parsing
            tree = fromstring(xml_bytes)

            # Depth limiting
            if get_xml_depth(tree) > MAX_XML_DEPTH:
                logger.warning(f"XML depth exceeds maximum allowed depth ({MAX_XML_DEPTH}).")
                return Response("XML depth exceeds the maximum allowed depth.", status=400, mimetype='text/plain')

            # Schema Validation (Optional - requires SCHEMA_FILE to be defined)
            # if SCHEMA_FILE:
            #     try:
            #         xmlschema_doc = lxml.etree.parse(SCHEMA_FILE)
            #         xmlschema = lxml.etree.XMLSchema(xmlschema_doc)
            #         xmlschema.assertValid(tree)
            #     except lxml.etree.XMLSchemaError as e:
            #         logger.error(f"XML schema validation error: {e}")
            #         return Response("XML does not conform to the schema.", status=400, mimetype='text/plain')
            #     except Exception as e:
            #         logger.exception("Error loading or validating XML schema")
            #         return Response("Error processing XML schema.", status=500, mimetype='text/plain')


        except lxml.etree.XMLSyntaxError as e:
            redacted_error = str(e).replace("<string>", "[XML]")  # Redact the source
            logger.error(f"Invalid XML syntax: {redacted_error}")
            return Response("Invalid XML syntax.", status=400, mimetype='text/plain')  # Generic error message
        except Exception as e:
            logger.exception("Error parsing XML")
            return Response("Error processing XML.", status=500, mimetype='text/plain')

        # Serialize the XML tree back to a string.  Use encoding='utf-8' for consistency.
        try:
            xml_string = tostring(tree, encoding='utf-8', pretty_print=True).decode('utf-8')
        except Exception as e:
            logger.exception("Error serializing XML")
            return Response("Error processing XML.", status=500, mimetype='text/plain')

        response = Response(xml_string, mimetype='application/xml')
        response.headers['X-Content-Type-Options'] = 'nosniff'  # Prevent content type sniffing
        response.headers['X-Frame-Options'] = 'DENY'  # Prevent clickjacking
        response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP
        response.headers['Referrer-Policy'] = 'no-referrer' # Control referrer information
        # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload' # HSTS - only enable if you have HTTPS
        return response

    except Exception as e:
        logger.exception("An unexpected error occurred")
        return Response("An unexpected error occurred.", status=500, mimetype='text/plain')


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production

