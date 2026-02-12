from flask import Flask, request, make_response, jsonify
import lxml.etree
from defusedxml.lxml import fromstring, tostring
import secrets
import os
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Generate a secret key for the app
app.secret_key = os.urandom(24)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)


@app.route('/get_token', methods=['GET'])
def get_token():
    """
    Generates a CSRF token and sets it as a cookie.  Returns the token in the response body as JSON.
    """
    token = secrets.token_hex(16)
    resp = make_response(jsonify({'csrf_token': token}))  # Return token in JSON
    resp.headers['Content-Type'] = 'application/json'  # Set Content-Type header
    resp.set_cookie('csrf_token', token, httponly=True, secure=True, samesite='Strict')  # Secure and HttpOnly flags
    logging.info("CSRF token generated and set as cookie.")
    return resp

@app.post("/parse_xml")
@limiter.limit("10 per minute")  # Apply rate limiting to the parse_xml endpoint
def parse_xml():
    '''
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string.
    :return: The XML as a string.
    '''
    token = request.cookies.get('csrf_token')
    form_token = request.form.get('csrf_token')

    if not token or not form_token or token != form_token:
        logging.warning("CSRF token mismatch")
        return "CSRF token mismatch", 400

    if request.content_type != 'application/x-www-form-urlencoded': # or 'multipart/form-data'
        logging.warning(f"Invalid Content-Type: {request.content_type}")
        return "Invalid Content-Type", 400

    xml_src = request.form.get('xml_src')

    if not xml_src:
        logging.warning("No XML source provided")
        return "No XML source provided", 400

    try:
        # Use defusedxml to parse the XML safely
        xml_doc = fromstring(xml_src)
        
        # Convert the XML back to a string
        xml_string = tostring(xml_doc, encoding="unicode")  # Explicitly specify encoding

        logging.info("XML parsed successfully")
        return xml_string, 200

    except lxml.etree.XMLSyntaxError as e:
        logging.error(f"XML parsing error: {str(e)}")
        return f"XML parsing error: {str(e)}", 400
    except Exception as e:
        logging.exception("An unexpected error occurred") # Use exception to log the full traceback
        return f"An unexpected error occurred: {str(e)}", 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

