from urllib.parse import urlparse
from flask import Flask, redirect, abort, request, make_response

app = Flask(__name__)

ALLOWED_DOMAINS = ["example.com", "www.example.com"]  # Define allowed domains

def redirect_url(url):
    """
    Redirects to the given URL if its domain is in the allowed list.
    Returns a 404 error if the domain is not allowed.

    Args:
        url (str): The URL to redirect to.

    Returns:
        flask.Response: A redirect response or a 404 error.
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc  # Get the network location (domain)
        
        # Validate the URL scheme (HTTPS is preferred)
        if parsed_url.scheme not in ['http', 'https']:
            print(f"Invalid URL scheme: {parsed_url.scheme}")
            abort(400, "Invalid URL scheme. Only HTTP and HTTPS are allowed.")

        if not domain:
            print(f"No domain found in URL: {url}")
            abort(400, "Invalid URL: No domain specified.")

        if domain in ALLOWED_DOMAINS:
            return redirect(url, code=302)  # Use 302 for temporary redirect
        else:
            print(f"Unauthorized redirect to domain: {domain}")
            abort(404)  # Return a 404 error for unauthorized domains

    except Exception as e:
        print(f"Error parsing URL: {e}")
        abort(400, "Invalid URL format.")  # Return a 400 error for invalid URL format


@app.route('/redirect')
def handle_redirect():
    """
    Handles the redirect request.  Expects a 'url' parameter in the request.
    """
    target_url = request.args.get('url')

    if not target_url:
        return "Missing 'url' parameter", 400

    return redirect_url(target_url)


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
    return response


@app.route('/')
def index():
    """
    Simple index route.
    """
    return "Welcome!  Use /redirect?url=<target_url> to test redirects."


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

