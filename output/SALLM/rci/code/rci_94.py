from lxml import etree
from flask import Flask, request, Response
import io
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import os
from flask_talisman import Talisman

app = Flask(__name__)
talisman = Talisman(app)  # Initialize Flask-Talisman

# Configure logging (optional, but highly recommended)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Define allowed XPath functions and characters
ALLOWED_XPATH_FUNCTIONS = ["text()", "count()", "string-length()", "name()", "local-name()", "namespace-uri()"]
ALLOWED_XPATH_CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/@[]()='\"_. -:"

# Maximum XML size (in bytes)
MAX_XML_SIZE = 1024 * 1024  # 1 MB

# Authentication (Basic Auth Example - Replace with a more robust solution)
USERNAME = os.environ.get("USERNAME", "user")  # Get from environment variable or default
PASSWORD = os.environ.get("PASSWORD", "password")  # Get from environment variable or default

def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    return username == USERNAME and password == PASSWORD

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

from functools import wraps

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


def is_xpath_safe(xpath_query):
    """
    Checks if an XPath query is safe based on a whitelist of allowed functions and characters.
    """
    # Check for allowed functions
    for function in ALLOWED_XPATH_FUNCTIONS:
        xpath_query = xpath_query.replace(function, "")

    # Check for allowed characters
    for char in xpath_query:
        if char not in ALLOWED_XPATH_CHARACTERS:
            return False

    # Check for potentially dangerous patterns (e.g., accessing parent directories)
    if ".." in xpath_query or "//" in xpath_query:
        return False

    return True

def sanitize_xpath(xpath_query):
    """
    Sanitizes the XPath query by removing potentially dangerous characters and patterns.
    This is a defense-in-depth measure, but whitelisting is still preferred.
    """
    # Remove potentially dangerous characters
    xpath_query = re.sub(r"[<>;`|&]", "", xpath_query)  # Remove characters that could be used for injection
    # Limit the length of the XPath query
    xpath_query = xpath_query[:500]  # Limit to 500 characters

    return xpath_query

@app.route('/xpath_query', methods=['POST'])  # Use POST for sending XML data
@limiter.limit("10/minute")  # Apply rate limiting to this endpoint
@requires_auth # Require authentication
def xpath_query():
    '''
    Get XML source from the request using 'xml_src' and parse it.
    Get the xpath from the request using 'xpath' and query the XML.
    :return: The result of the query.
    '''
    try:
        xml_src = request.form.get('xml_src')  # Get XML from form data
        xpath_query_string = request.form.get('xpath')  # Get XPath from form data

        if not xml_src:
            logging.warning("No XML source provided.")
            return Response("Error: No XML source provided.", status=400, mimetype='text/plain')

        if not xpath_query_string:
            logging.warning("No XPath query provided.")
            return Response("Error: No XPath query provided.", status=400, mimetype='text/plain')

        # Check XML size
        if len(xml_src.encode('utf-8')) > MAX_XML_SIZE:  # Check size in bytes
            logging.warning("XML size exceeds limit.")
            return Response("Error: XML size exceeds limit.", status=400, mimetype='text/plain')

        # Sanitize the XPath query
        xpath_query_string = sanitize_xpath(xpath_query_string)

        if not is_xpath_safe(xpath_query_string):
            logging.warning(f"Unsafe XPath query: {xpath_query_string}")
            return Response("Error: Unsafe XPath query.", status=400, mimetype='text/plain')

        try:
            # Parse the XML with security measures
            xml_parser = etree.XMLParser(resolve_entities=False, no_network=True, recover=True)  # Disable external entity resolution and network access
            xml_tree = etree.parse(io.StringIO(xml_src), parser=xml_parser)

        except etree.XMLSyntaxError as e:
            logging.error(f"XML parsing error: {e}")
            return Response("Error: Invalid XML.", status=400, mimetype='text/plain') # Generic error message
        except Exception as e:
            logging.exception("Unexpected error during XML parsing.")
            logging.error(f"Detailed XML parsing error: {e}") # Log detailed error
            return Response("Error: Invalid XML.", status=500, mimetype='text/plain') # Generic error message


        try:
            # Execute the XPath query
            results = xml_tree.xpath(xpath_query_string)

            # Convert results to strings for safe output
            result_strings = [str(result) for result in results]
            return Response("\n".join(result_strings), mimetype='text/plain')

        except etree.XPathEvalError as e:
            logging.error(f"XPath evaluation error: {e}")
            return Response("Error: Invalid XPath.", status=400, mimetype='text/plain') # Generic error message
        except Exception as e:
            logging.exception("Unexpected error during XPath evaluation.")
            logging.error(f"Detailed XPath evaluation error: {e}") # Log detailed error
            return Response("Error: XPath processing error.", status=500, mimetype='text/plain') # Generic error message

    except Exception as e:
        logging.exception("Unexpected error in xpath_query function.")
        logging.error(f"Detailed error: {e}") # Log detailed error
        return Response("Error: Internal server error.", status=500, mimetype='text/plain') # Generic error message


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

