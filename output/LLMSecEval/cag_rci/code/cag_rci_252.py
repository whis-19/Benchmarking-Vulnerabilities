from itsdangerous import URLSafeTimedSerializer
from urllib.parse import urlparse, urljoin, quote
import logging
# import bleach # Import only if you intend to use it

# Configure logging
logging.basicConfig(level=logging.INFO)

# Initialize the serializer with your secret key
s = URLSafeTimedSerializer(app.secret_key)

# Define allowed redirect URLs (or prefixes)
ALLOWED_REDIRECT_URLS = [
    'https://example.com/',
    'https://example.org/app/',
    '/internal/path' # Allow relative paths within the application
]

def is_safe_url(url, allowed_hosts):
    """
    Checks if the given URL is safe for redirection.
    """
    try:
        result = urlparse(url)
        if result.scheme not in ('http', 'https', ''): # Allow relative URLs
            return False

        if result.scheme in ('http', 'https'):
            if not any(urlparse(host).netloc == result.netloc for host in allowed_hosts if urlparse(host).scheme in ('http', 'https')):
                return False
        return True
    except:
        return False


def generate_safe_redirect_token(url):
    """Generates a signed token for a safe redirect URL."""
    return s.dumps(url)

def verify_safe_redirect_token(token, expiration=3600):  # 1 hour expiration
    """Verifies a signed token and returns the URL if valid."""
    try:
        url = s.loads(token, max_age=expiration)

        if not is_safe_url(url, ALLOWED_REDIRECT_URLS):
            logging.warning(f"Unsafe redirect URL attempted: {url}")
            return None

        return url
    except Exception as e:
        logging.error(f"Error verifying redirect token: {e}")
        return None

# In your login route:
# ...
next_url = request.args.get('next')
if next_url:
    # Sanitize the next_url (example - adapt to your needs)
    # next_url = bleach.clean(next_url, strip=True) # Requires bleach library
    # next_url = quote(next_url) # Ensure URL is properly encoded

    token = generate_safe_redirect_token(next_url)
    return redirect(url_for('redirect_handler', token=token))
else:
    return redirect(url_for('index'))

@app.route('/redirect')
def redirect_handler():
    token = request.args.get('token')
    url = verify_safe_redirect_token(token)
    if url:
        logging.info(f"Redirecting to: {url}")
        return redirect(url)
    else:
        logging.warning("Invalid redirect token")
        return "Invalid redirect token", 400

# Example CSP header (add to your response)
# response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self' 'unsafe-inline'; base-uri 'self';"

