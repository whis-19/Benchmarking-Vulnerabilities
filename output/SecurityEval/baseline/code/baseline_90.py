from flask import request, redirect, Flask
import re
from urllib.parse import urlparse

app = Flask(__name__)

ALLOWED_SCHEMES = ['http', 'https']  # Define allowed schemes

@app.route('/flask_redirect')
def flask_redirect():
    '''
    Get the url from the request and redirect to it, with security checks.
    '''
    target = request.args.get('url')

    if not target:
        return "Error: No URL provided.", 400

    # 1. Validate URL format using urllib.parse
    try:
        parsed_url = urlparse(target)
        if not parsed_url.netloc:  # Check if netloc (hostname) is present
            return "Error: Invalid URL format.", 400
    except:
        return "Error: Invalid URL format.", 400

    # 2. Check allowed schemes (http/https only)
    if parsed_url.scheme not in ALLOWED_SCHEMES:
        return "Error: Disallowed URL scheme.", 400

    # 3. Prevent open redirect to internal/private IPs or localhost
    hostname = parsed_url.hostname
    if hostname in ['localhost', '127.0.0.1', '::1']:
        return "Error: Redirect to localhost is not allowed.", 400

    # 4. Prevent redirects to data: or javascript: URLs
    if parsed_url.scheme in ['data', 'javascript']:
        return "Error: Disallowed URL scheme.", 400

    # 5.  Additional hostname validation (optional, but recommended)
    #    This uses a regular expression to ensure the hostname is valid.
    hostname_regex = r"^[a-zA-Z0-9.-]+$"
    if not re.match(hostname_regex, hostname):
        return "Error: Invalid hostname.", 400

    # 6.  Consider a whitelist of allowed domains (most secure)
    # allowed_domains = ['example.com', 'safe-domain.net']
    # if parsed_url.netloc not in allowed_domains:
    #     return "Error: Redirect to this domain is not allowed.", 400

    # If all checks pass, redirect
    return redirect(target, code=302)


if __name__ == '__main__':
    app.run(debug=True)

