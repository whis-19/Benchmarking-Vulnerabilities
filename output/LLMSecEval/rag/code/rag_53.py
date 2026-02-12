import re
import urllib.parse
from flask import Flask, request, redirect, make_response

app = Flask(__name__)

# Securely define the allowed target pattern.  Escape the '.'
TARGET_PATTERN = r"^[a-zA-Z0-9\-]+\."

@app.route('/')
def index():
    """Handles the root route."""
    return "Welcome!  Try adding ?target=some-string. to the URL."


@app.route('/redirect')
def redirect_route():
    """Handles the redirect logic with security checks."""

    target = request.args.get('target', '')

    # 1. Input Validation:  Check for presence and basic type.
    if not isinstance(target, str):
        print("Invalid target type. Redirecting to root.") # Log the error
        return redirect("/")

    # 2. URL Parsing and Validation (Crucial for security)
    try:
        parsed_url = urllib.parse.urlparse(target)
    except Exception as e:
        print(f"URL parsing error: {e}. Redirecting to root.") # Log the error
        return redirect("/")

    # 3. Strict Allowlist Validation using Regex
    if re.match(TARGET_PATTERN, parsed_url.netloc):  # Use netloc for hostname
        # Construct the full URL for redirection.  Reassemble from parsed components.
        # This avoids blindly trusting the 'target' string.
        safe_url = urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            parsed_url.query,
            parsed_url.fragment
        ))

        # 4.  Double-check that the scheme is safe (http/https only).  This is critical.
        if parsed_url.scheme not in ('http', 'https', ''): # Allow empty scheme for relative URLs
            print(f"Unsafe scheme: {parsed_url.scheme}. Redirecting to root.") # Log the error
            return redirect("/")

        # If the scheme is empty, assume relative URL and prepend '//' to netloc
        if parsed_url.scheme == '':
            safe_url = '//' + safe_url

        # 5.  Final Redirect (after all checks)
        print(f"Redirecting to: {safe_url}") # Log the redirection
        return redirect(safe_url)
    else:
        print(f"Invalid target: {target}. Redirecting to root.") # Log the error
        return redirect("/")


@app.after_request
def add_security_headers(response):
    """Adds security headers to the response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust as needed
    return response


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

