from flask import Flask, request, make_response
from defusedxml.ElementTree import fromstring, ParseError
import xml.etree.ElementTree as ET
import bleach
import logging
import xmlschema  # For XML Schema validation (optional)

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load the XML schema (optional)
try:
    schema = xmlschema.XMLSchema('your_schema.xsd')  # Replace with your schema file
except xmlschema.XMLSchemaError as e:
    logging.warning(f"Error loading XML schema: {e}")
    schema = None  # Disable schema validation if loading fails


@app.after_request
def add_header(response):
    response.headers['Content-Type'] = 'application/xml; charset=utf-8'
    return response


@app.post("/upload")
def upload():
    xml_data = request.data

    try:
        root = fromstring(xml_data)

        # Validate against the schema if it was loaded successfully (optional)
        if schema:
            try:
                schema.validate(root)
            except xmlschema.XMLSchemaValidationError as e:
                logging.warning(f"XML Schema Validation Error: {e}")
                return f"XML Schema Validation Error: {e}", 400

        # Define the expected XML structure and validation rules
        expected_root_tag = "data"
        expected_item_tag = "item"
        expected_item_id_attribute = "id"

        # Validate the root element
        if root.tag != expected_root_tag:
            logging.warning(f"Invalid root element: Expected '{expected_root_tag}', got '{root.tag}'")
            return f"Invalid root element: Expected '{expected_root_tag}', got '{root.tag}'", 400

        data = {}
        for element in root.findall(f'.//{expected_item_tag}'):
            # Validate element name
            if element.tag != expected_item_tag:
                logging.warning(f"Invalid element name: Expected '{expected_item_tag}'")
                return f"Invalid element name: Expected '{expected_item_tag}'", 400

            # Validate attributes
            item_id = element.get(expected_item_id_attribute)
            if not item_id:
                logging.warning(f"Missing '{expected_item_id_attribute}' attribute in <{expected_item_tag}> element")
                return f"Missing '{expected_item_id_attribute}' attribute in <{expected_item_tag}> element", 400

            # Validate data type (example: ensure 'id' is an integer)
            try:
                item_id = int(item_id)  # Convert to integer if valid
                if item_id > 2**31 - 1:  # Example overflow check (adjust as needed)
                    logging.warning(f"Integer overflow detected: item_id is too large")
                    return "Integer overflow detected: item_id is too large", 400
            except ValueError:
                logging.warning(f"Invalid '{expected_item_id_attribute}' attribute: Must be an integer")
                return f"Invalid '{expected_item_id_attribute}' attribute: Must be an integer", 400

            # Extract text content and sanitize it
            item_text = element.text
            if item_text:
                # Configure bleach
                allowed_tags = ['p', 'b', 'i', 'em', 'strong']
                allowed_attributes = {'a': ['href', 'rel']}
                item_text = bleach.clean(item_text, tags=allowed_tags, attributes=allowed_attributes)  # Sanitize for HTML output
                data[item_id] = item_text
            else:
                data[item_id] = ""

        # Create a response (replace with your actual logic)
        # Instead of echoing back the input, return a standardized JSON response
        # This is just an example; adapt to your needs
        response_data = {"status": "success", "data": data}
        import json
        response = make_response(json.dumps(response_data), 200)
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
        return response

    except ParseError as e:
        logging.error(f"XML Parsing Error: {e}")
        return f"XML Parsing Error: {e}", 400
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full traceback
        return f"An unexpected error occurred: {e}", 500


if __name__ == '__main__':
    app.run(debug=False)

