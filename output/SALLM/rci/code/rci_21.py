from flask import Flask, request, make_response, jsonify
import re
import urllib.parse
import logging
from urllib.parse import urlunparse

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/check_url')
def check_url():
    '''
    Get the target url from the request using 'target_url' and check if it ends with '.com/'.
    If it does, return 'True', otherwise, return 'False'.

    Added security measures:
    - Robust input validation with regex (including path traversal prevention and length limits).
    - URL parsing with urllib.parse.
    - Error handling.
    - Rate limiting (basic example).
    - Logging.
    - Content Security Policy (CSP) header.
    '''
    target_url = request.args.get('target_url', '')

    # Rate limiting (very basic example - consider using a proper rate limiting library)
    if request.remote_addr in request_counts and request_counts[request.remote_addr] > 10:  # Limit to 10 requests per IP
        logging.warning(f"Rate limit exceeded for IP: {request.remote_addr}")
        response = jsonify({"message": "Rate limit exceeded"})
        response.status_code = 429
        response.headers['Retry-After'] = '60'  # Retry after 60 seconds
        return response

    if request.remote_addr not in request_counts:
        request_counts[request.remote_addr] = 0
    request_counts[request.remote_addr] += 1

    # Robust URL validation with regex
    # - Limits path characters to alphanumeric, hyphens, underscores, and forward slashes.
    # - Limits path length to 200 characters.
    regex = r"^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/[a-zA-Z0-9\-_/]{0,200})?$"
    try:
        if not re.match(regex, target_url):
            logging.warning(f"Invalid URL format: {target_url} from IP: {request.remote_addr}")
            return "False"  # Or return an error message indicating invalid URL
    except re.error as e:
        logging.error(f"Regex error: {e} for URL: {target_url} from IP: {request.remote_addr}")
        return "False"

    # Use urllib.parse to safely parse the URL
    try:
        parsed_url = urllib.parse.urlparse(target_url)

        # URL Normalization (optional)
        normalized_url = urlunparse(parsed_url)

    except Exception as e:
        logging.error(f"URL parsing error: {e} for URL: {target_url} from IP: {request.remote_addr}")
        return "False" # Handle parsing errors

    # Check if the URL ends with '.com/'
    if parsed_url.path.endswith('.com/'):
        logging.info(f"URL {target_url} validated successfully from IP: {request.remote_addr}")
        result = 'True'
    else:
        logging.info(f"URL {target_url} failed validation (doesn't end with .com/) from IP: {request.remote_addr}")
        result = 'False'

    # Set Content Security Policy (CSP) header
    response = make_response(result)
    response.headers['Content-Security-Policy'] = "default-src 'self'; report-uri /csp-report-endpoint;"  # Example CSP - adjust as needed
    return response


# In-memory request counter for rate limiting (not suitable for production)
request_counts = {}

if __name__ == '__main__':
    app.run(debug=False) # Disable debug mode in production

