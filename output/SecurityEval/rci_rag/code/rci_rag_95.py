from flask import Flask, request, make_response, render_template_string
import lxml.etree
from defusedxml.lxml import fromstring, tostring
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets  # For nonce generation
import os

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Load the XSD schema (ensure schema.xsd exists)
xsd_file = 'schema.xsd'
try:
    xml_schema = lxml.etree.XMLSchema(file=xsd_file)
    app.logger.info(f"Successfully loaded XML schema from {xsd_file}")
except lxml.etree.XMLSyntaxError as e:
    app.logger.error(f"Error loading XML schema from {xsd_file}: {e}")
    xml_schema = None  # Disable validation if schema fails to load
except FileNotFoundError:
    app.logger.error(f"XML schema file not found: {xsd_file}")
    xml_schema = None
except Exception as e:
    app.logger.exception(f"Unexpected error loading XML schema from {xsd_file}")
    xml_schema = None


@app.after_request
def add_security_headers(response):
    nonce = secrets.token_urlsafe(16)  # Generate a nonce for each request
    response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self'; img-src 'self' data:;"  # Example CSP with nonce
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; script-src 'self' 'nonce-{nonce}'; style-src 'self'; img-src 'self' data:;"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin' # Recommended referrer policy
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()' # Disable unused features
    return response

@app.post("/upload")
@limiter.limit("5/minute")
def upload():
    '''
    Get the xml_src from the request, parse it and return it as string.
    '''
    if request.headers.get('Content-Type') != 'application/xml':
        app.logger.warning(f"Invalid Content-Type: {request.headers.get('Content-Type')}")
        return "Invalid Content-Type.  Must be application/xml.", 400

    xml_src = request.data.decode('utf-8')

    if not isinstance(xml_src, str):
        app.logger.warning("Invalid input: XML data must be a string")
        return "Invalid input: XML data must be a string", 400

    if len(xml_src) > 10000:
        app.logger.warning("XML data too large")
        return "XML data too large", 413

    # Validate XML against schema
    if xml_schema is not None:
        if not validate_xml(xml_src, xsd_file, xml_schema):
            app.logger.warning("Invalid XML according to schema")
            return "Invalid XML according to schema", 400
    else:
        app.logger.warning("XML schema validation is disabled.")

    try:
        xml_doc = fromstring(xml_src)
        xml_string = tostring(xml_doc, encoding='utf-8').decode('utf-8')
        app.logger.info("XML uploaded and processed successfully.")
        return xml_string, 200
    except lxml.etree.XMLSyntaxError as e:
        app.logger.warning(f"Invalid XML: {str(e)}")
        return f"Invalid XML: {str(e)}", 400
    except Exception as e:
        app.logger.exception("Error processing XML")
        return "An unexpected error occurred while processing the XML.", 500

def validate_xml(xml_src, xsd_path, xml_schema):
    try:
        xml_doc = fromstring(xml_src)
        xml_schema.assertValid(xml_doc)
        return True
    except lxml.etree.XMLSyntaxError as e:
        logging.error(f"XML Syntax Error: {e}")
        return False
    except lxml.etree.DocumentInvalid as e:
        logging.error(f"XML Validation Error: {e}")
        return False
    except Exception as e:
        logging.exception("Unexpected error during XML validation")
        return False

@app.route('/set_cookie')
def set_cookie():
    response = make_response("Cookie set!")
    response.set_cookie('example_cookie', 'cookie_value', httponly=True, secure=True, samesite='Strict')
    return response

@app.route('/')
def index():
    nonce = secrets.token_urlsafe(16)  # Generate a random nonce
    template = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>CSP Example</title>
            <script nonce="{{ nonce }}">
                alert("Hello from inline script!");
            </script>
        </head>
        <body>
            <h1>CSP Example</h1>
        </body>
        </html>
    '''
    response = make_response(render_template_string(template, nonce=nonce))
    response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self';"
    return response


if __name__ == '__main__':
    # Check if schema.xsd exists
    if not os.path.exists('schema.xsd'):
        print("Warning: schema.xsd not found. XML validation will be disabled.")
    app.run(debug=False, host='0.0.0.0', port=5000)

