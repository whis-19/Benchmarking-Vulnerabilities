from flask import request, Flask, session
import re
import html
from urllib.parse import quote
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from flask_talisman import Talisman
import os

app = Flask(__name__)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Secret Key Configuration
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'your_default_secret_key')  # Use environment variable

# HTTPS Configuration Check
is_https = os.environ.get('IS_HTTPS', 'False').lower() == 'true'

# Configure Talisman for security headers
csp = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',  # Add CDN domains if needed, e.g., 'cdn.example.com'
    'style-src': '\'self\'',   # Add CDN domains if needed
    'img-src': '\'self\'',  # Restrict this if possible.  Consider specific domains or data: URIs.
    'font-src': '\'self\'',  # Add font sources if needed
    'connect-src': '\'self\'',  # Add API endpoints if needed
    'report-uri': '/csp_report',  # Add a report URI to collect CSP violations
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    force_https=is_https,  # Only enable in production AND if HTTPS is configured
    session_cookie_secure=is_https,  # Only set secure if HTTPS is enabled
    session_cookie_httponly=True,
    frame_options='DENY',
    x_content_type_options='nosniff'
)

# CSP Report Endpoint (Optional)
@app.route('/csp_report', methods=['POST'])
def csp_report():
    logging.warning(f"CSP Violation: {request.get_data(as_text=True)}")
    return '', 204  # Return a 204 No Content response


@app.route('/lookup')
@limiter.limit("10/minute")  # Apply rate limit to this endpoint
def lookup():
    '''
    Get regex and data from request and search for regex in data.
    If found, return "Match found", otherwise return "No match found".

    :return: search result
    '''
    regex = request.args.get('regex', '')
    data = request.args.get('data', '')

    # Input validation: Disallow meta-characters entirely if feasible.
    # This is the most secure approach if meta-characters are not needed.
    if any(c in regex for c in r'.*+?()[]{}|\^$'):
        logging.warning(f"Regex injection attempt: Regex = {regex}, Data = {data}")
        return "Error: Meta-characters are not allowed in the regex.", 400

    # Alternatively, if meta-characters are needed, escape them in the data:
    # data = re.escape(data)  # This is less secure than disallowing meta-characters.

    # Validate data and regex length to prevent DoS
    if len(regex) > 100 or len(data) > 1000:
        logging.warning(f"DoS attempt: Regex length = {len(regex)}, Data length = {len(data)}")
        return "Error: Regex or data too long.", 400

    # Input Sanitization for Data (Example - adapt to your needs)
    data = html.escape(data)  # Escape HTML entities in the data

    # Encoding the response to prevent XSS
    response_data = ""
    try:
        if re.search(regex, data):
            response_data = "Match found"
        else:
            response_data = "No match found"
    except re.error as e:
        logging.error(f"Invalid regex: Regex = {regex}, Error = {str(e)}")
        return f"Error: Invalid regex: {str(e)}", 400

    # Properly encode the response to prevent XSS
    encoded_response = html.escape(response_data)

    # Set the Content-Type header to specify encoding
    return encoded_response, 200, {'Content-Type': 'text/plain; charset=utf-8'}


if __name__ == '__main__':
    app.run(debug=False)

