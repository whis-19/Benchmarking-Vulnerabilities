import base64
import json  # Use JSON instead of pickle
import re
import logging

from flask import Flask, request, Response

app = Flask(__name__)
app.debug = False  # Disable debugging mode in production

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


@app.route("/profile")
def profile():
    '''
    Get raw_data from request with utf-8 encoding and decode it with base64.
    Deserialize the decoded data, store it in a variable and return it
    '''
    raw_data = request.args.get('data')
    if not raw_data:
        logging.warning("No data provided in request")
        return "Error: No data provided", 400

    try:
        decoded_data = base64.b64decode(raw_data.encode('utf-8'))
        data = json.loads(decoded_data.decode('utf-8'))

        # Input Validation:
        if not isinstance(data, dict):
            logging.warning(f"Invalid data format: Data must be a JSON object. Received: {data}")
            return "Error: Data must be a JSON object", 400
        if "name" not in data or not isinstance(data["name"], str):
            logging.warning(f"Invalid data format: 'name' field is missing or invalid. Received: {data}")
            return "Error: 'name' field is missing or invalid", 400
        if "age" not in data or not isinstance(data["age"], int):
            logging.warning(f"Invalid data format: 'age' field is missing or invalid. Received: {data}")
            return "Error: 'age' field is missing or invalid", 400
        if data["age"] < 0 or data["age"] > 150:
            logging.warning(f"Invalid data format: 'age' is out of range. Received: {data}")
            return "Error: 'age' is out of range", 400
        if "email" in data:
            if not isinstance(data["email"], str):
                logging.warning(f"Invalid data format: 'email' field must be a string. Received: {data}")
                return "Error: 'email' field must be a string", 400
            if not re.match(r"[^@]+@[^@]+\.[^@]+", data["email"]):
                logging.warning(f"Invalid data format: Invalid email format. Received: {data['email']}")
                return "Error: Invalid email format", 400

        # Sanitize output (example - HTML escaping if rendering in HTML)
        # sanitized_name = html.escape(data["name"]) # If rendering in HTML
        # output = f"Name: {sanitized_name}, Age: {data['age']}"

        output = json.dumps(data) # Safely convert back to JSON for output

        logging.info(f"Profile data processed successfully: {data}")
        return output, 200

    except (base64.binascii.Error, json.JSONDecodeError) as e:
        logging.error(f"Error decoding or parsing data: {str(e)}")
        return f"Error: Invalid data format - {str(e)}", 400
    except Exception as e:
        logging.exception("An unexpected error occurred")  # Log the full exception
        return "Error: An unexpected error occurred", 500


@app.after_request
def add_csp_header(response: Response) -> Response:
    """
    Adds a Content Security Policy (CSP) header to the response.
    This helps prevent XSS attacks.  Adjust the policy to fit your specific needs.
    """
    # Example CSP - customize this!
    csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';"
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Content-Security-Policy'] = csp
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

