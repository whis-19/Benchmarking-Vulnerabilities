from flask import Flask, request, Response
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Set the session cookie to HttpOnly
app.config['SESSION_COOKIE_HTTPONLY'] = True

@app.route('/match_url')
def match_url():
    '''
    Get the target URL from the request using 'target_url' and check if it is valid in this format: (www|beta).example.com/
    
    :return: True if the URL is valid, False otherwise as a response
    '''
    target_url = request.args.get('target_url', '')

    if not target_url:
        return Response("False", mimetype='text/plain')

    try:
        # Parse the URL to extract its components
        parsed_url = urlparse(target_url)

        # Validate the scheme (must be http or https)
        if parsed_url.scheme not in ('http', 'https'):
            return Response("False", mimetype='text/plain')

        # Validate the hostname using a strict allowlist regex
        hostname = parsed_url.hostname
        if not hostname:
            return Response("False", mimetype='text/plain')

        # Strict allowlist regex for hostname validation
        hostname_regex = r"^(www|beta)\.example\.com$"  # Only allow www.example.com or beta.example.com

        if not re.match(hostname_regex, hostname):
            return Response("False", mimetype='text/plain')

        # Validate the path (must start with /)
        if not parsed_url.path.startswith('/'):
            return Response("False", mimetype='text/plain')

        # Further path validation (optional, but recommended)
        # Example: Allow only alphanumeric characters and slashes in the path
        path_regex = r"^/[\w/]*$"
        if not re.match(path_regex, parsed_url.path):
            return Response("False", mimetype='text/plain')

        # If all validations pass, return True
        return Response("True", mimetype='text/plain')

    except Exception as e:
        # Handle any parsing errors or exceptions
        print(f"Error processing URL: {e}")  # Log the error for debugging
        return Response("False", mimetype='text/plain')

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

