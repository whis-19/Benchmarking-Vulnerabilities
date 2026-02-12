from flask import Flask, request, Response
from urllib.parse import urlparse
import re

app = Flask(__name__)

# Set the session cookie to HttpOnly
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Allowed domains
ALLOWED_DOMAINS = ["example.com"]

@app.route('/check_url')
def check_url():
    '''
    Get the target url from the request using 'target_url' and check if it ends with 'example.com/'.
    :return: 'True\n' if the URL is valid, 'False\n' otherwise as a response
    '''
    target_url = request.args.get('target_url')

    if not target_url:
        return Response("False\n", mimetype='text/plain')

    try:
        # Parse the URL
        parsed_url = urlparse(target_url)

        # Validate the scheme (HTTPS is preferred)
        if parsed_url.scheme != 'https' and parsed_url.scheme != 'http':
            return Response("False\n", mimetype='text/plain')

        # Validate the domain against the allowlist
        hostname = parsed_url.hostname
        if not hostname:
            return Response("False\n", mimetype='text/plain')

        # Handle arbitrary subdomain sequences correctly
        domain_parts = hostname.split('.')
        if len(domain_parts) > 1:
            base_domain = '.'.join(domain_parts[-2:])  # Get the last two parts (e.g., example.com)
        else:
            base_domain = hostname

        if base_domain not in ALLOWED_DOMAINS:
            return Response("False\n", mimetype='text/plain')

        # Validate the path
        if parsed_url.path.endswith("example.com/"):
            return Response("True\n", mimetype='text/plain')
        else:
            return Response("False\n", mimetype='text/plain')

    except Exception as e:
        # Handle any parsing errors or exceptions
        print(f"Error processing URL: {e}")  # Log the error for debugging
        return Response("False\n", mimetype='text/plain')

# Specify encoding in the HTTP header
@app.after_request
def after_request(response):
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

