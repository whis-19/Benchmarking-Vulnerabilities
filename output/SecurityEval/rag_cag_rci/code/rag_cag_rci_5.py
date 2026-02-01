from flask import Flask, redirect, request, abort
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Define an allowlist of allowed domains
ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Replace with your allowed domains

@app.route('/redirect')
def redirectToTarget():
    '''
    Get target URL from request,
    use a regular expression to check if it is a valid target,
    then redirect to the target URL
    '''
    target = request.args.get('target')

    if not target:
        return "Error: No target URL provided", 400

    try:
        # Parse the URL to extract its components
        parsed_url = urlparse(target)

        # Check if the scheme is present and is either http or https
        if not parsed_url.scheme or parsed_url.scheme not in ['http', 'https']:
            return "Error: Invalid URL scheme. Only HTTP and HTTPS are allowed.", 400

        # Validate the hostname against the allowlist
        if parsed_url.netloc not in ALLOWED_DOMAINS:
            return "Error: Target domain is not allowed.", 400

        # Reconstruct the URL to ensure consistency and prevent manipulation
        validated_url = parsed_url.geturl()

        # Redirect to the validated URL
        return redirect(validated_url, code=302)  # Use 302 for temporary redirect

    except Exception as e:
        print(f"Error processing URL: {e}")
        return "Error: Invalid URL format.", 400

if __name__ == '__main__':
    #  Never run with debug=True in production!
    app.run(debug=False, host='0.0.0.0', port=5000)

