from flask import Flask, request, Response
import re
from urllib.parse import urlparse
import logging
import validators

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Configure logging
logging.basicConfig(level=logging.INFO)  # Or logging.DEBUG for more verbose output

# Strict whitelist of allowed hostnames
ALLOWED_HOSTNAMES = ["www.example.com", "beta.example.com"]

@app.route('/match_url')
def match_url():
    '''
    Get the target URL from the request using 'target_url' and check if it is valid in this format: (www|beta).example.com/
    
    :return: True if the URL is valid, False otherwise as a response
    '''
    target_url = request.args.get('target_url', '')

    # Validate the data in the request
    if not target_url:
        logging.warning("Empty target_url received.")
        return Response("False", mimetype='text/plain')

    # Validate the URL format using validators library
    if not validators.url(target_url):
        logging.warning(f"Invalid URL format: {target_url}")
        return Response("False", mimetype='text/plain')

    # Parse the URL
    try:
        parsed_url = urlparse(target_url)
    except ValueError:
        logging.warning(f"Invalid URL: {target_url}")
        return Response("False", mimetype='text/plain')

    # Check the scheme
    if parsed_url.scheme not in ('http', 'https'):
        logging.warning(f"Invalid scheme: {parsed_url.scheme}")
        return Response("False", mimetype='text/plain')

    # Stringent allowlist validation for the hostname
    hostname = parsed_url.netloc
    if not hostname:
        logging.warning("No hostname found in URL.")
        return Response("False", mimetype='text/plain')

    # Check if the hostname is in the allowlist
    if hostname in ALLOWED_HOSTNAMES:
        return Response("True", mimetype='text/plain')
    else:
        logging.warning(f"Hostname not in allowlist: {hostname}")
        return Response("False", mimetype='text/plain')

if __name__ == '__main__':
    app.run(debug=False)

