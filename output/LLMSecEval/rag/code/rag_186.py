import re
import urllib.parse
from flask import Flask, request, redirect, make_response

app = Flask(__name__)

# Securely define the allowed target pattern.  Escape the '.'
TARGET_PATTERN = r"^[a-zA-Z0-9\-]+\."

@app.route('/')
def index():
    """Handles the root route."""
    return "Welcome!  Try adding ?target=some-safe-url.com"

@app.route('/redirect')
def redirect_route():
    """Handles the redirect route with target validation."""

    target = request.args.get('target', '')

    if not target:
        return redirect("/")  # Redirect to root if no target is provided

    try:
        # Parse the URL to handle subdomains and other URL components correctly.
        parsed_url = urllib.parse.urlparse(target)

        # Validate the scheme.  Only allow http/https.  Crucial security step.
        if parsed_url.scheme not in ('http', 'https', ''):  # Allow empty scheme for relative URLs
            print(f"Invalid scheme: {parsed_url.scheme}")
            return redirect("/")

        # Validate the netloc (hostname).  This is the most important part.
        if parsed_url.netloc:
            if not re.match(TARGET_PATTERN, parsed_url.netloc):
                print(f"Invalid netloc: {parsed_url.netloc}")
                return redirect("/")
        else:
            # Handle relative URLs.  Be very careful with these.  Only allow if you *really* trust the input.
            # In this example, we are explicitly disallowing them for increased security.
            print("Relative URLs are disallowed.")
            return redirect("/")


        # Reconstruct the URL to ensure consistency and prevent manipulation.
        # This is important to prevent bypassing the validation.
        if parsed_url.netloc:
            validated_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment))
        else:
            validated_url = parsed_url.path # Only use the path for relative URLs

        print(f"Redirecting to: {validated_url}")
        return redirect(validated_url)

    except Exception as e:
        print(f"Error parsing URL: {e}")
        return redirect("/")  # Redirect to root on any error

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

