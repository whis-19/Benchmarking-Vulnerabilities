import re
from urllib.parse import urlparse, quote
from flask import escape, request, Flask  # For output sanitization
import logging

app = Flask(__name__)

ALLOWED_DOMAINS = ["example.com", "api.example.com"]  # Explicitly allowed domains

def validate_url(url):
    """Validates and sanitizes a URL."""
    try:
        result = urlparse(url)
        if all([result.scheme, result.netloc]):  # Check for scheme and netloc
            # Check if the domain is in the allowlist (exact match)
            if result.netloc in ALLOWED_DOMAINS:
                if result.scheme == 'https': # Enforce HTTPS
                    return url  # URL is valid and allowed
                else:
                    logging.warning(f"URL scheme is not HTTPS: {result.scheme}")
                    return None
            else:
                logging.warning(f"URL domain not in allowlist: {result.netloc}")
                return None  # Domain not allowed
        else:
            return None  # Invalid URL
    except:
        return None  # Invalid URL

@app.route('/api/example', methods=['GET'])
def example_endpoint():
    """Example endpoint demonstrating output sanitization."""
    user_input = request.args.get('input', '')  # Get user input

    # Sanitize the output using flask.escape (HTML encoding)
    sanitized_input = escape(user_input)

    # Return the sanitized input
    return f"You entered: {sanitized_input}"

if __name__ == '__main__':
    app.run(debug=True)

