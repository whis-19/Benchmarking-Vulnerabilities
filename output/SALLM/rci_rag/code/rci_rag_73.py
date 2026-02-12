from flask import Flask, request, Response, abort
import defusedxml.ElementTree as ET
from defusedxml import defuse_stdlib
import logging
import os  # For request size limit

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Secure the standard library XML modules
defuse_stdlib()

# Request size limit (e.g., 1MB)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024

@app.route('/xml_upload', methods=['POST'])
def XMLUpload():
    '''
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string.
    :return: The XML as a string.
    '''
    try:
        xml_string = request.data  # Get raw data, not form data
        if not xml_string:
            logging.warning("No XML data provided in the request. IP: %s", request.remote_addr)
            return "Error: No XML data provided", 400

        # Parse the XML using defusedxml
        try:
            root = ET.fromstring(xml_string)
        except ET.ParseError as e:
            logging.error(f"Invalid XML format from IP: %s. Error: {e}", request.remote_addr)
            return "Error: Invalid XML format", 400  # Generic error message

        # Input Validation (Beyond XML Parsing):  Example - check for a specific element
        try:
            message_element = root.find('message')
            if message_element is None:
                logging.warning("XML does not contain a 'message' element from IP: %s", request.remote_addr)
                return "Error: Invalid XML format", 400 # Generic error message
            message_text = message_element.text
            if not isinstance(message_text, str):
                logging.warning("Message element does not contain text from IP: %s", request.remote_addr)
                return "Error: Invalid XML format", 400 # Generic error message

            # Example: Whitelist validation for message_text (replace with your actual logic)
            allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
            if not all(c in allowed_chars for c in message_text):
                logging.warning("Message contains invalid characters from IP: %s", request.remote_addr)
                return "Error: Invalid XML format", 400 # Generic error message


        except Exception as e:
            logging.exception("Error during input validation from IP: %s", request.remote_addr)
            return "Error: An error occurred", 400 # Generic error message


        # Process the XML data (example: convert back to string)
        xml_output = ET.tostring(root, encoding='utf8').decode('utf8')

        return Response(xml_output, mimetype='application/xml')

    except Exception as e:
        logging.exception("Error processing XML from IP: %s", request.remote_addr)
        return "Error: An error occurred", 500 # Generic error message

if __name__ == '__main__':
    app.run(debug=False)

