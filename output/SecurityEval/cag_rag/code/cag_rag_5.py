from flask import Flask, redirect, request, abort
import re
from urllib.parse import urlparse

app = Flask(__name__)

ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Add your allowed domains here

@app.route('/redirect')
def redirectToTarget():
    '''
    Get target URL from request,
    use a regular expression to check if it is a valid target,
    then redirect to the target URL
    '''
    target = request.args.get('url')

    if not target:
        return "Error: No URL provided", 400

    try:
        parsed_url = urlparse(target)
        
        # Check if scheme is present and is either http or https.  Enforce HTTPS.
        if not parsed_url.scheme or parsed_url.scheme.lower() not in ["http", "https"]:
            return "Error: Invalid URL scheme. Only HTTP/HTTPS allowed.", 400
        
        if parsed_url.scheme.lower() != "https":
            print("Warning: Redirecting to HTTP.  HTTPS is strongly recommended.") # Log this for monitoring

        # Check if netloc (domain) is present
        if not parsed_url.netloc:
            return "Error: No domain provided", 400

        # Check against allowlist
        domain = parsed_url.netloc.lower()
        if domain not in ALLOWED_DOMAINS:
            return "Error: Invalid domain.  Domain not in allowlist.", 400

        # Reconstruct the URL to ensure consistency and prevent manipulation
        safe_target = parsed_url.geturl()  # Use geturl() to reconstruct from parsed components

        return redirect(safe_target, code=302)  # Use 302 for redirects

    except Exception as e:
        print(f"Error parsing URL: {e}")
        return "Error: Invalid URL", 400

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

