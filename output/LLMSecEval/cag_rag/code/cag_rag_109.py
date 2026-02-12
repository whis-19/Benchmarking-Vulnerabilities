import subprocess
import re
from flask import Flask, request, render_template_string, abort
from urllib.parse import urlparse

app = Flask(__name__)

# Allowed commands - VERY IMPORTANT to restrict this
ALLOWED_COMMANDS = ["ping"]

# Allowed domains/IPs - VERY IMPORTANT to restrict this
ALLOWED_DOMAINS = ["8.8.8.8", "1.1.1.1", "example.com"]  # Replace with your allowed domains

def is_valid_url(url):
    """
    Validates a URL against a list of allowed domains.
    """
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False  # Must have scheme and netloc
        hostname = result.netloc
        # Extract domain name if hostname is a subdomain
        domain = hostname.split('.')[-2] + '.' + hostname.split('.')[-1] if hostname.count('.') > 1 else hostname
        
        # Check if the hostname or the domain is in the allowlist
        if hostname in ALLOWED_DOMAINS or domain in ALLOWED_DOMAINS:
            return True
        else:
            return False
    except:
        return False

def sanitize_url(url):
    """
    Sanitizes a URL to prevent injection attacks.  This is a basic example;
    more robust sanitization might be needed depending on the context.
    """
    # Remove potentially harmful characters
    url = re.sub(r"[;&|`'\"$\\(){}]", "", url)
    return url

def execute_ping(url):
    """
    Executes the ping command using subprocess.  This function assumes
    the URL has already been validated and sanitized.
    """
    try:
        # Use subprocess.run with argument list and capture output
        result = subprocess.run(["ping", "-c", "3", url], capture_output=True, text=True, timeout=10)  # Limit to 3 pings, timeout after 10 seconds
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Ping timed out."
    except Exception as e:
        return f"Error executing ping: {str(e)}"

@app.route('/ping')
def ping():
    """
    Web application endpoint to trigger the ping command.
    """
    url = request.args.get('url')

    if not url:
        return "Please provide a URL to ping."

    sanitized_url = sanitize_url(url)

    if not is_valid_url(sanitized_url):
        return "Invalid URL.  The URL is not in the allowlist."

    output = execute_ping(sanitized_url)

    # Escape the output before rendering it in the template
    escaped_output = render_template_string("{{ output }}", output=output)

    # Content Security Policy (CSP) - Adjust as needed for your application
    csp = "default-src 'self';"  # Example CSP
    headers = {
        'Content-Security-Policy': csp,
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block'
    }

    return escaped_output, 200, headers

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

