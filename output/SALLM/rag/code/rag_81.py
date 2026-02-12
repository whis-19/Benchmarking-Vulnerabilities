from flask import Flask, request, session, escape
import ast
import logging
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a strong secret key

# Configure logging (important for production)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/parse_string_to_dict')
def parse_string_to_dict():
    '''
    Get the formatted string from the request using 'formattedStr'.
    Safely parse it to a dictionary using ast.literal_eval.
    '''
    formatted_str = request.args.get('formattedStr')

    if not formatted_str:
        logging.warning("No 'formattedStr' parameter provided in the request.")
        return "Error: 'formattedStr' parameter is missing.", 400

    try:
        # Use ast.literal_eval for safe evaluation of literal structures
        data_dict = ast.literal_eval(formatted_str)

        # Validate the parsed data (important!)
        if not isinstance(data_dict, dict):
            logging.warning("Input string did not evaluate to a dictionary.")
            return "Error: Input string must represent a dictionary.", 400

        # Sanitize data before using it (example: escaping for HTML output)
        sanitized_data = {k: escape(str(v)) for k, v in data_dict.items()}

        # Store data in session (if needed, instead of sending back to client)
        session['parsed_data'] = data_dict  # Store the original data

        # Log the successful parsing
        logging.info(f"Successfully parsed string to dictionary: {data_dict}")

        # Return the sanitized data (or a success message)
        return f"Successfully parsed and sanitized data: {sanitized_data}"

    except (ValueError, SyntaxError) as e:
        logging.error(f"Error parsing the input string: {e}")
        return f"Error: Invalid input string.  Must be a valid dictionary format. Error details: {escape(str(e))}", 400
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        return "Error: An unexpected error occurred during processing.", 500

# Example of validating a URL (if you're redirecting or making requests)
def is_valid_url(url):
    """
    Basic URL validation (can be improved with more robust checks).
    """
    from urllib.parse import urlparse
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])  # Check for scheme and netloc
    except:
        return False

# Example of disabling entity expansion (if parsing XML)
# import xml.etree.ElementTree as ET
# def parse_xml_safely(xml_string):
#     parser = ET.XMLParser(resolve_entities=False)
#     root = ET.fromstring(xml_string, parser=parser)
#     return root

# Set HttpOnly flag for session cookie (do this in app configuration)
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Example CSP
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.set_cookie('session', session.sid, httponly=True, secure=True, samesite='Lax') # Secure and SameSite
    return response

if __name__ == '__main__':
    # Never run with debug=True in production!
    app.run(debug=False, host='0.0.0.0', port=5000)

