import xml.etree.ElementTree as ET
from flask import Flask, request, abort
import defusedxml.ElementTree as DET
import logging
import bleach  # For content sanitization
import os  # For file extension validation
from werkzeug.utils import secure_filename # For secure filename handling

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Maximum XML file size (in bytes) to prevent denial-of-service attacks
MAX_XML_SIZE = 100000  # Adjust this value based on your needs

# Allowed XML file extensions
ALLOWED_EXTENSIONS = {'xml'}

# Secret key for CSRF protection (replace with a strong, randomly generated key)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a random secret key

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/xml_upload', methods=['POST'])
def XMLUpload():
    '''
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string.
    :return: The XML as a string.
    '''
    if 'xml_src' not in request.files:
        logging.warning("No xml_src file part in request")
        return "No xml_src file part", 400

    xml_file = request.files['xml_src']

    if xml_file.filename == '':
        logging.warning("No file selected")
        return "No selected file", 400

    # Validate file extension
    if not allowed_file(xml_file.filename):
        logging.warning(f"Invalid file extension: {xml_file.filename}")
        return "Invalid file extension", 400

    # Secure filename
    filename = secure_filename(xml_file.filename)
    if filename != xml_file.filename:
        logging.warning(f"Invalid filename: {xml_file.filename}. Secure filename is: {filename}")
        return "Invalid filename", 400

    try:
        xml_data = xml_file.read()

        # Check file size to prevent denial-of-service attacks
        if len(xml_data) > MAX_XML_SIZE:
            logging.warning(f"XML file size exceeds limit: {len(xml_data)} > {MAX_XML_SIZE}")
            return "XML file too large", 413  # Request Entity Too Large

        # Use defusedxml to prevent XML vulnerabilities like XXE and Billion Laughs
        # defusedxml disables external entity resolution by default, preventing the parser from accessing external resources that could be exploited in an XXE attack.
        # defusedxml includes limits on entity expansion to prevent the parser from being overwhelmed by recursively defined entities, which can lead to a denial-of-service.
        try:
            root = DET.fromstring(xml_data)
        except DET.ParseError as e:
            logging.error(f"XML Parsing Error: {e}")
            return f"XML Parsing Error: {e}", 400

        # Sanitize the XML data (example: remove potentially harmful attributes)
        # This is crucial to prevent XSS and other injection attacks.
        sanitize_xml(root)

        # Convert the sanitized XML back to a string
        xml_string = ET.tostring(root, encoding='utf-8').decode('utf-8')

        logging.info(f"Successfully processed XML file: {filename}") # Log successful upload

        return xml_string, 200, {'Content-Type': 'application/xml'}

    except IOError as e:
        logging.error(f"IOError reading XML file: {e}")
        return "Error reading XML file", 500
    except Exception as e:
        logging.exception(f"Error processing XML: {e}")  # Log the full exception with traceback
        return "Error processing XML", 500


def sanitize_xml(element):
    """
    Recursively sanitize an XML element by removing potentially harmful attributes and content.
    This is a crucial security measure to prevent XSS and other injection attacks.
    `onload`, `onclick`, and `onerror` attributes can be used to execute arbitrary JavaScript code when the XML is rendered in a browser.
    `src` and `href` attributes can be used to load external resources, potentially leading to XSS or other vulnerabilities.
    """
    # Define a list of *allowed* attributes (use allowlisting instead of denylisting)
    allowed_attributes = {'id', 'class', 'title'}  # Example: adjust based on your needs

    # Remove attributes that are not in the allowlist
    for attribute in list(element.attrib):  # Iterate over a copy to allow deletion
        if attribute not in allowed_attributes:
            del element.attrib[attribute]

    # Sanitize the text content of the element
    if element.text:
        element.text = bleach.clean(element.text, strip=True)
    if element.tail:
        element.tail = bleach.clean(element.tail, strip=True) # Sanitize tail text

    # Recursively sanitize child elements
    for child in element:
        sanitize_xml(child)


if __name__ == '__main__':
    app.run(debug=True)

