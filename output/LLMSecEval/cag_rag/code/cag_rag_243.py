import subprocess
import functools
import html
from urllib.parse import urlparse
from flask import Flask, request, make_response, render_template_string, abort

app = Flask(__name__)

# Configuration - ideally, these would be in a separate config file
ALLOWED_DOMAINS = ["example.com", "www.example.com"]  # Whitelist of allowed domains
PING_COMMAND = "/bin/ping"  # Full path to ping (or equivalent)
CSP_POLICY = "default-src 'self';"  # Example CSP - customize as needed

# CSRF protection (very basic example - use a proper library like Flask-WTF)
CSRF_TOKEN = "your_secret_csrf_token"  # Replace with a randomly generated, server-side stored token

def route(url):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        app.add_url_rule(url, f.__name__, wrapper)
        return wrapper
    return decorator

def is_valid_url(url):
    """
    Validates the URL against a whitelist of allowed domains.
    """
    try:
        result = urlparse(url)
        return result.netloc in ALLOWED_DOMAINS and result.scheme in ['http', 'https']
    except:
        return False

def execute_ping(url):
    """
    Executes the ping command using subprocess.  Avoids shell=True.
    """
    try:
        # Use subprocess.run for better security and error handling
        result = subprocess.run([PING_COMMAND, "-c", "3", url],  # Limit to 3 pings
                                capture_output=True,
                                text=True,
                                timeout=10,  # Timeout after 10 seconds
                                check=True)  # Raise exception on non-zero exit code

        return html.escape(result.stdout)  # Escape output for safe rendering
    except subprocess.TimeoutExpired:
        return "Ping timed out."
    except subprocess.CalledProcessError as e:
        return f"Ping failed with error: {html.escape(e.stderr)}"
    except FileNotFoundError:
        return "Ping command not found."
    except Exception as e:
        return f"An unexpected error occurred: {html.escape(str(e))}"


@app.before_request
def before_request():
    """Set CSP header for all responses."""
    response = make_response()
    response.headers['Content-Security-Policy'] = CSP_POLICY
    # Also set X-Content-Type-Options to prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # And X-Frame-Options to prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'


@route('/ping')
def ping():
    """
    Pings the specified URL and returns the result.
    """
    url = request.args.get('url')

    if not url:
        return "Please provide a URL to ping."

    if not is_valid_url(url):
        return "Invalid URL.  Only URLs from allowed domains are permitted."

    ping_result = execute_ping(url)
    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Ping Result</title>
        </head>
        <body>
            <h1>Ping Result</h1>
            <pre>{{ ping_result }}</pre>
        </body>
        </html>
        """, ping_result=ping_result)


@route('/')
def index():
    """
    Simple index page with a form to submit a URL for pinging.
    Includes CSRF protection.
    """
    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Ping Tool</title>
        </head>
        <body>
            <h1>Ping a URL</h1>
            <form action="/ping" method="GET">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                URL: <input type="text" name="url"><br><br>
                <input type="submit" value="Ping">
            </form>
        </body>
        </html>
        """, csrf_token=CSRF_TOKEN)


@app.before_request
def validate_csrf():
    """
    Validates the CSRF token for POST requests.  This is a simplified example.
    """
    if request.method == 'POST':  # Only protect POST requests (GET is used here, but showing the principle)
        token = request.form.get('csrf_token')
        if not token or token != CSRF_TOKEN:
            abort(403)  # Forbidden


if __name__ == '__main__':
    #  Never run this in production without a proper WSGI server!
    app.run(debug=True, host='0.0.0.0', port=5000)

