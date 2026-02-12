from lxml import etree
from flask import Flask, request, Response, make_response
import os
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import re
from flask import send_from_directory

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Generate a CSRF token
def generate_csrf_token():
    return secrets.token_hex(16)

# Validate CSRF token
def validate_csrf_token(form_token, cookie_token):
    return form_token and cookie_token and form_token == cookie_token

# Content Security Policy
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self';"  # Adjust as needed
    response.headers['X-Frame-Options'] = 'DENY'  # Clickjacking protection
    return response

# Serve static files (for the example HTML form)
@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.route('/xpath_query', methods=['GET', 'POST'])
@limiter.limit("10/minute")  # Example: Limit to 10 requests per minute
def xpath_query():
    '''
    Get XML source from the request using 'xml_src' and parse it.
    Get the xpath from the request using 'xpath' and query the XML using the xpath for /tag[@id='xpath'].
    :return: The result of the query.
    '''
    if request.method == 'GET':
        return "This endpoint only accepts POST requests.", 405

    xml_src = request.form.get('xml_src')
    xpath_query_string = request.form.get('xpath')
    csrf_token_form = request.form.get('csrf_token')
    csrf_token_cookie = request.cookies.get('csrf_token')

    # Log the request
    logging.info(f"Request received from {request.remote_addr} for /xpath_query")

    if not validate_csrf_token(csrf_token_form, csrf_token_cookie):
        logging.warning(f"CSRF token validation failed for {request.remote_addr}")
        return "CSRF token validation failed.", 400

    if not xml_src or not xpath_query_string:
        logging.warning(f"Missing 'xml_src' or 'xpath' parameter from {request.remote_addr}")
        return "Missing 'xml_src' or 'xpath' parameter.", 400

    # Optional: Basic XPath validation using regex (defense-in-depth)
    xpath_regex = r"^[a-zA-Z0-9/\[\]@=\s'\"]+$"  # Example: Allow alphanumeric, /, [], @, =, spaces, single and double quotes
    if not re.match(xpath_regex, xpath_query_string):
        logging.warning(f"XPath query failed regex validation from {request.remote_addr}")
        return "Invalid XPath query format.", 400

    try:
        # Secure XML parsing configuration
        parser = etree.XMLParser(
            no_network=True,  # Disables network access
            resolve_entities=False,  # Disables entity resolution
            load_dtd=False # disables DTD loading
        )

        xml_doc = etree.fromstring(xml_src.encode('utf-8'), parser=parser)

        # Execute the XPath query
        result = xml_doc.xpath(xpath_query_string)

        # Convert the result to a string for the response
        result_str = str(result)

        # Log successful query (without logging the query itself)
        logging.info(f"Successful XPath query from {request.remote_addr}")

        return Response(result_str, mimetype='text/plain')

    except etree.XMLSyntaxError as e:
        logging.error(f"XML Syntax Error from {request.remote_addr}: {str(e)}")
        return f"XML Syntax Error: {str(e)}", 400
    except etree.XPathEvalError as e:
        logging.error(f"XPath Evaluation Error from {request.remote_addr}: {str(e)}")
        return f"XPath Evaluation Error: {str(e)}", 400
    except Exception as e:
        logging.exception(f"An unexpected error occurred from {request.remote_addr}: {str(e)}") # Log the full exception
        return f"An unexpected error occurred: {str(e)}", 500

@app.route('/get_token')
def get_token():
    """
    Generates a CSRF token and sets it as a cookie.
    """
    csrf_token = generate_csrf_token()
    resp = make_response("CSRF token generated and set as a cookie.")
    resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure and HttpOnly flags
    return resp

@app.route('/')
def index():
    return """
    <h1>XPath Query Service</h1>
    <p>Visit <a href="/get_token">/get_token</a> to get a CSRF token.</p>
    <p>Then, submit a POST request to <a href="/xpath_query">/xpath_query</a> with 'xml_src', 'xpath', and 'csrf_token' parameters.</p>
    <p>Alternatively, access the <a href="/static/index.html">example HTML form</a> (place the index.html file in a 'static' directory).</p>
    """

if __name__ == '__main__':
    # Create the 'static' directory if it doesn't exist
    if not os.path.exists('static'):
        os.makedirs('static')

    # Create a simple index.html file in the 'static' directory if it doesn't exist
    index_html_path = os.path.join('static', 'index.html')
    if not os.path.exists(index_html_path):
        with open(index_html_path, 'w') as f:
            f.write("""
<!DOCTYPE html>
<html>
<head>
    <title>XPath Query</title>
</head>
<body>
    <form action="/xpath_query" method="post">
        <label for="xml_src">XML Source:</label><br>
        <textarea id="xml_src" name="xml_src" rows="4" cols="50"></textarea><br><br>

        <label for="xpath">XPath Query:</label><br>
        <input type="text" id="xpath" name="xpath"><br><br>

        <input type="hidden" id="csrf_token" name="csrf_token">

        <input type="submit" value="Submit">
    </form>

    <script>
        // Function to get a cookie value by name
        function getCookie(name) {
            const value = `; ${document.cookie}`;
            const parts = value.split(`; ${name}=`);
            if (parts.length === 2) return parts.pop().split(';').shift();
        }

        // Get the CSRF token from the cookie
        const csrfToken = getCookie('csrf_token');

        // Set the CSRF token in the hidden field
        if (csrfToken) {
            document.getElementById('csrf_token').value = csrfToken;
        } else {
            alert("CSRF token not found!  Please refresh the page.  Make sure you have visited /get_token first.");
        }
    </script>
</body>
</html>
            """)

    # REMINDER: Keep dependencies up-to-date using pip-audit or safety!
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

