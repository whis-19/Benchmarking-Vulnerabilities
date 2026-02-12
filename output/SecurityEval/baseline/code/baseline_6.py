from flask import Flask, redirect, request
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Define a list of allowed domains.  This should be as restrictive as possible.
ALLOWED_DOMAINS = [
    "example.com",  # Replace with your allowed domains
    "www.example.com",
    "subdomain.example.com"
]

@app.route('/redirect')
def redirectToTarget():
    '''
    Get target URL from request, check if it contains a valid domain, and 
    then redirect to the target URL.  Implements robust security checks to prevent open redirects.
    '''
    target = request.args.get('url')

    if not target:
        return "Error: No URL provided.", 400  # Bad Request

    try:
        parsed_url = urlparse(target)
        hostname = parsed_url.hostname

        if not hostname:
            return "Error: Invalid URL.", 400

        # Check if the hostname is in the allowed list.  Case-insensitive comparison.
        if hostname.lower() not in [domain.lower() for domain in ALLOWED_DOMAINS]:
            return "Error: Invalid domain.", 400

        # Further validation: Ensure the scheme is either http or https.
        if parsed_url.scheme not in ("http", "https"):
            return "Error: Invalid scheme. Only HTTP and HTTPS are allowed.", 400

        # Additional security:  Sanitize the URL to prevent injection attacks.
        # This example uses a simple regex to remove potentially dangerous characters.
        #  Adjust the regex as needed based on your specific requirements.
        sanitized_url = re.sub(r"[<>\"']", "", target)  # Remove <, >, ", '

        # Redirect to the sanitized URL.  Use a 302 redirect for temporary redirects.
        return redirect(sanitized_url, code=302)

    except Exception as e:
        print(f"Error processing URL: {e}")  # Log the error for debugging
        return "Error: Invalid URL format.", 400


if __name__ == '__main__':
    app.run(debug=True)

