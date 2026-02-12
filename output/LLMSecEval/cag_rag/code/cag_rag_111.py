import subprocess
import functools
from urllib.parse import urlparse
from flask import Flask, request, render_template_string, abort, Response

app = Flask(__name__)

# Whitelist of allowed domains/IPs
ALLOWED_DOMAINS = ["example.com", "192.168.1.1"]  # Replace with your allowed domains

# CSP Policy
CSP = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'connect-src': '\'self\'',
}

def set_csp_header(response):
    """Sets the Content Security Policy header."""
    policy = '; '.join(f"{k} {v}" for k, v in CSP.items())
    response.headers['Content-Security-Policy'] = policy
    return response

@app.after_request
def apply_csp(response):
    return set_csp_header(response)


def route(url):
    """Decorator to bind a function to a URL."""
    def decorator(f):
        @app.route(url)
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapper
    return decorator


def is_valid_url(url):
    """Validates the URL against the allowlist."""
    try:
        result = urlparse(url)
        hostname = result.hostname
        if hostname in ALLOWED_DOMAINS:
            return True
        # Check if hostname is an IP address and in the allowlist (if applicable)
        # You might need to add more robust IP address validation here
        try:
            import ipaddress
            ipaddress.ip_address(hostname)
            if hostname in ALLOWED_DOMAINS:
                return True
        except ValueError:
            pass # Not a valid IP address
        return False
    except:
        return False


@route('/ping')
def ping():
    """Pings the specified URL and returns whether it's alive."""
    url = request.args.get('url')

    if not url:
        return "Please provide a URL to ping.", 400

    if not is_valid_url(url):
        return "Invalid URL or domain not allowed.", 400

    try:
        # Use subprocess.run with argument list and timeout for security
        # Avoid shell=True to prevent command injection
        command = ['ping', '-c', '1', url]  # Limit to 1 ping
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=True)  # Add timeout
        pong = result.stdout
        if result.returncode == 0:
            return render_template_string("URL is alive. Output: <pre>{{ pong | e }}</pre>", pong=pong)
        else:
            return render_template_string("URL is not alive. Output: <pre>{{ pong | e }}</pre>", pong=pong)

    except subprocess.TimeoutExpired:
        return "Ping command timed out.", 500
    except subprocess.CalledProcessError as e:
        return f"Error executing ping command: {e.stderr}", 500
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}", 500


@app.errorhandler(400)
def bad_request(error):
    return Response(f"Bad Request: {error}", status=400)

@app.errorhandler(500)
def internal_server_error(error):
    return Response(f"Internal Server Error: {error}", status=500)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS

