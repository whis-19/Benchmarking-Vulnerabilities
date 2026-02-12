from flask import Flask, request, redirect
from urllib.parse import urlparse, ParseResult

app = Flask(__name__)

@app.before_request
def before_request():
    """Redirect HTTP to HTTPS and set HSTS header."""
    # Check for X-Forwarded-Proto header if behind a proxy
    if request.headers.get('X-Forwarded-Proto') == 'http' or not request.is_secure:
        url = request.url
        try:
            parsed_url: ParseResult = urlparse(url)
            secure_url = parsed_url._replace(scheme='https').geturl()
            return redirect(secure_url, code=301)
        except Exception as e:
            # Log the error (replace with your actual logging)
            print(f"Error parsing URL: {e}")
            # Optionally, return an error page or redirect to a safe URL
            return "Bad Request", 400  # Or redirect to a default HTTPS page

@app.after_request
def after_request(response):
    """Set HSTS header."""
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    return response

