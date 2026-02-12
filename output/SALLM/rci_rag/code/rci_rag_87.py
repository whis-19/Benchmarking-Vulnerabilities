from flask import Flask, request, make_response, Markup, escape
import defusedxml.ElementTree as ET
import os
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import defusedxml.lxml as safe_lxml
from lxml import etree

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Store the secret key securely (e.g., environment variable)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379",  # Use a persistent storage in production (e.g., redis://)
)


def validate_xml(xml_src, xsd_path):
    """Validates XML against an XSD schema."""
    try:
        xml_doc = safe_lxml.fromstring(xml_src)
        xml_schema = etree.XMLSchema(file=xsd_path)  # Load XSD from file
        xml_schema.assertValid(xml_doc)
        return True, None
    except etree.XMLSyntaxError as e:
        return False, f"XML Syntax Error: {str(e)}"
    except etree.XMLSchemaError as e:
        return False, f"XSD Schema Error: {str(e)}"
    except etree.DocumentInvalid as e:
        return False, f"XML Validation Error: {str(e)}"
    except Exception as e:
        return False, f"Unexpected Validation Error: {str(e)}"


@app.route("/upload", methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Apply rate limiting to the upload route
def upload():
    '''
    Get the data from the request using 'xml_src'.
    Parse it as XML from the string using defusedxml.
    :return: The XML as a string.
    '''
    if request.method == 'POST':
        xml_src = request.form.get('xml_src')

        # CSRF protection: Verify the token
        csrf_token = request.form.get('csrf_token')
        cookie_token = request.cookies.get('csrf_token')

        if not csrf_token or not cookie_token or csrf_token != cookie_token:
            return "CSRF token validation failed.", 400

        if xml_src:
            try:
                # Validate against XSD
                is_valid, validation_error = validate_xml(xml_src, "your_schema.xsd") # Replace with your XSD file
                if not is_valid:
                    return f"XML Validation Failed: {validation_error}", 400

                root = ET.fromstring(xml_src)

                # Sanitize data (example - escaping for HTML output)
                for element in root.findall(".//*"):  # Iterate through all elements
                    if element.text:
                        element.text = str(escape(element.text)) # Escape HTML entities

                xml_string = ET.tostring(root, encoding='utf8').decode('utf8')
                return xml_string, 200

            except ET.ParseError as e:
                return f"XML Parsing Error: {str(e)}", 400
            except Exception as e:
                logger.exception("An unexpected error occurred during XML processing:") # Log the full exception
                return "An unexpected error occurred. Please check the logs.", 500 # User-friendly message
        else:
            return "No XML data provided.", 400
    else: # GET request - serve the upload form with CSRF protection
        token = secrets.token_hex(16)
        resp = make_response('''
            <form method="post" action="/upload">
                <input type="hidden" name="csrf_token" value="''' + token + '''">
                <textarea name="xml_src" rows="10" cols="50"></textarea><br>
                <input type="submit" value="Upload XML">
            </form>
        ''')
        resp.set_cookie('csrf_token', token, httponly=True, samesite='Strict', secure=True) # Secure cookie
        # CSP Header
        resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;"
        return resp


@app.after_request
def add_security_headers(response):
    # Prevent ClickJacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Prevent MIME-sniffing vulnerabilities
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Enable XSS filtering (usually enabled by default, but good to be explicit)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    return response


if __name__ == '__main__':
    #  Do not use debug=True in production
    #  HTTPS is essential in production
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use 'adhoc' for testing only.  Use proper certificates in production.

