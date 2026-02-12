from flask import Flask, redirect, request, abort, url_for, session
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import os
from flask_talisman import Talisman
import tldextract
import ipaddress  # For CIDR notation
from flask_wtf.csrf import CSRFProtect # CSRF Protection

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a strong secret key
talisman = Talisman(app,
                    force_https=True,
                    hsts_max_age=31536000,
                    hsts_include_subdomains=True,
                    hsts_preload=True,
                    content_security_policy={  # Example CSP
                        'default-src': '\'self\'',
                        'script-src': '\'self\' https://example.com',
                        'style-src': '\'self\' https://example.com',
                        'img-src': '\'self\' data:'
                    },
                    session_cookie_secure=True,  # Ensure cookies are only sent over HTTPS
                    session_cookie_httponly=True, # Prevent client-side script access
                    session_cookie_samesite='Lax', # CSRF protection
                    x_frame_options='SAMEORIGIN', # Clickjacking protection
                    x_content_type_options='nosniff', # MIME sniffing protection
                    referrer_policy='strict-origin-when-cross-origin' # Referrer policy
                    )

csrf = CSRFProtect(app) # CSRF Protection

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Example configuration (load from environment variables or a config file)
ALLOWED_DOMAINS = os.environ.get("ALLOWED_DOMAINS", "").split(",")
ALLOWED_IPS = os.environ.get("ALLOWED_IPS", "").split(",")

# Example user database (replace with a real database)
users = {
    'user1': generate_password_hash('password123'),
    'user2': generate_password_hash('secure_password')
}

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

def is_valid_ip(ip_address):
    """Validates if the provided IP address is valid."""
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def is_ip_in_network(ip_address, network):
    """Checks if an IP address is within a given network (CIDR notation)."""
    try:
        return ipaddress.ip_address(ip_address) in ipaddress.ip_network(network)
    except ValueError:
        return False

@app.before_request
def before_request():
    """
    Enforce HTTPS and domain/IP allowlist.
    """
    # 7. Use HTTPS for all sensitive communications
    if not request.is_secure and app.env != "development":  # Only enforce in production
        url = request.url.replace("http://", "https://", 1)
        code = 301  # Permanent redirect
        return redirect(url, code=code)

    # 6. Implement allowlists for allowed domains/IPs
    if ALLOWED_DOMAINS:  # Check if the list is not empty
        parsed_uri = urlparse(request.url)
        domain = parsed_uri.netloc
        if domain not in ALLOWED_DOMAINS:
            logger.warning(f"Blocked request from domain: {domain} to URL: {request.url}")
            abort(403)  # Forbidden

    if ALLOWED_IPS:  # Check if the list is not empty
        client_ip = request.remote_addr
        allowed = False
        for allowed_ip in ALLOWED_IPS:
            if '/' in allowed_ip:  # CIDR notation
                if is_ip_in_network(client_ip, allowed_ip):
                    allowed = True
                    break
            elif is_valid_ip(client_ip) and client_ip == allowed_ip:
                allowed = True
                break
        if not allowed:
            logger.warning(f"Blocked request from IP: {client_ip} to URL: {request.url}")
            abort(403)  # Forbidden

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Input validation (example)
        if not (username and password):
            return "Username and password are required", 400

        if len(username) < 3 or len(username) > 20:
            return "Username must be between 3 and 20 characters", 400

        # Add more validation as needed (e.g., character restrictions)

        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            session.permanent = True  # Make session permanent
            return redirect(url_for('protected'))
        else:
            logger.warning(f"Failed login attempt for username: {username} from IP: {request.remote_addr}")
            return "Invalid username or password", 401  # Unauthorized - Generic message
    return '''
        <form method="post">
            <p><input type=text name=username>
            <p><input type=password name=password>
            <p><input type=submit value=Login>
        </form>
    '''

@app.route('/redirect')
def redirect_url():
    target_url = request.args.get('url')

    # 5. Validate and sanitize all URLs
    if not target_url:
        return "No URL provided", 400

    try:
        result = urlparse(target_url)
        if not all([result.scheme, result.netloc]):
            logger.warning(f"Invalid URL: {target_url} - Missing scheme or netloc")
            return "Invalid URL", 400

        # Check if the scheme is allowed (HTTPS is preferred)
        if result.scheme not in ['http', 'https']:
            logger.warning(f"Invalid URL: {target_url} - Invalid scheme: {result.scheme}")
            return "Invalid URL scheme", 400

        # Disallow data: URI scheme
        if result.scheme == 'data':
            logger.warning(f"Blocked redirect to data: URI: {target_url}")
            return "Invalid URL scheme", 400

        # Check if the domain is in the allowlist (if applicable)
        extracted = tldextract.extract(target_url)
        domain = extracted.domain + "." + extracted.suffix

        if ALLOWED_DOMAINS and domain not in ALLOWED_DOMAINS:
            logger.warning(f"Blocked redirect to unauthorized domain: {domain} from URL: {target_url}")
            return "Unauthorized domain", 403

        logger.info(f"Redirecting to: {target_url}")
        return redirect(target_url)

    except ValueError as e:  # Catch specific exceptions
        logger.exception(f"URL parsing error for URL: {target_url}: {e}")
        return "Invalid URL", 400
    except Exception as e: # Be more specific here
        logger.exception(f"Unexpected error processing URL: {target_url}: {e}")
        return "Invalid URL", 400

@app.route('/protected')
def protected():
    if 'username' in session:
        return f'Logged in as {session["username"]}'
    return 'You are not logged in'

if __name__ == '__main__':
    # 8. Validate SSL/TLS certificates:  This is handled by the web server (e.g., nginx, Apache)
    #    when configuring HTTPS.  Flask itself doesn't directly handle certificate validation.
    #    Ensure your web server is configured to properly validate certificates.

    # Never run in debug mode in production!
    # app.run(debug=True, ssl_context='adhoc') # Use adhoc for local testing only.  NEVER in production.
    # For production, use a proper WSGI server (e.g., gunicorn, uWSGI) and configure HTTPS there.
    app.run(debug=True) # Remove ssl_context for clarity and add instructions elsewhere

