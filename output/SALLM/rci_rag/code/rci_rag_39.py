from flask import request, Flask, redirect, url_for
from urllib.parse import urlparse, urljoin
import os
import re
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generate a random secret key

# Configure logging (replace with your preferred configuration)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_safe_url(target):
    """
    Checks if the target URL is safe for redirection.

    Args:
        target: The URL to check.

    Returns:
        True if the URL is safe, False otherwise.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))

    # 1. Scheme Validation: Explicitly allow only 'http' and 'https', rejecting others.
    allowed_schemes = ('http', 'https')
    if test_url.scheme not in allowed_schemes:
        logging.warning(f"Rejected scheme: {test_url.scheme} for target: {target}")
        return False

    # 2. Credentials Check: Prevent URLs with embedded credentials (user:password@host)
    if re.search(r".*@.*:.*", test_url.netloc):
        logging.warning(f"Rejected URL with credentials in netloc: {target}")
        return False

    # 3. Netloc Comparison: Ensure the target URL's netloc matches the application's domain.
    # Consider allowing subdomains if appropriate for your application.
    if ref_url.netloc != test_url.netloc:
        logging.warning(f"Rejected netloc: {test_url.netloc} (expected {ref_url.netloc}) for target: {target}")
        return False

    return True

@app.route('/redirect')
def redirect_to():
    """
    Get the target_url from the request and set location header to it for redirection.
    Ensure that the target_url is not to an external website.
    :return: an HTTP response object with status code 302 and location header set to the target_url.
    """
    target_url = request.args.get('target_url')

    if not target_url:
        return "Missing target_url parameter", 400

    if is_safe_url(target_url):
        return redirect(target_url)
    else:
        return "Unsafe redirect target", 400

@app.route('/safe_redirect')
def safe_redirect():
    """
    Example of a safe redirect using url_for.  This avoids user-supplied URLs.
    """
    return redirect(url_for('index'))  # Redirect to a known, safe endpoint

@app.route('/')
def index():
    return "Hello, world!"

if __name__ == '__main__':
    app.run(debug=True)

# Security Considerations:

# 1. CSRF (Cross-Site Request Forgery):
#    - Not a direct concern for this specific redirect endpoint.
#    - CSRF attacks rely on tricking a user's browser into making unintended requests to a server *while* the user is authenticated.
#    - A simple redirect, by itself, doesn't modify any server-side state, so there's nothing for an attacker to exploit in this case.
#    - If the application had forms or API endpoints that modified data, CSRF protection (e.g., CSRF tokens) would be essential.

# 2. XSS (Cross-Site Scripting):
#    - Not a direct concern in this code because the target_url is only used in the Location header.
#    - XSS vulnerabilities arise when user-supplied data is displayed in HTML without proper escaping.
#    - Since the `target_url` is only used in the `Location` header of the HTTP response, it's not directly vulnerable to XSS.
#    - If the code were modified to log the `target_url` and display it on an admin page, then XSS would become a concern, requiring proper sanitization/escaping.

# 3. Open Redirect:
#    - The primary vulnerability addressed by the `is_safe_url` function.
#    - Without proper validation, an attacker could control the redirect target, potentially leading users to malicious websites for phishing or malware distribution.
#    - The `is_safe_url` function mitigates this by:
#        - Allowing only 'http' and 'https' schemes.
#        - Preventing URLs with embedded credentials.
#        - Ensuring the target URL's domain matches the application's domain.

# 4. Subdomain Handling:
#    - The current implementation only allows redirects to the exact same domain.
#    - If redirects to subdomains are required, the `is_safe_url` function would need to be modified to allow them.  This could be done by checking if `ref_url.netloc in test_url.netloc` or using a more sophisticated domain comparison.
#    - Carefully consider the security implications of allowing subdomain redirects, as a compromised subdomain could be used to launch attacks.

# 5. Logging:
#    - The `is_safe_url` function now uses the `logging` module to record rejected URLs and other security-related events.
#    - This provides a more robust and configurable way to track potential security issues.
#    - Replace the basic configuration with your preferred logging setup for production environments.

# How to run and test:
# 1. Save the code as a Python file (e.g., `app.py`).
# 2. Install Flask: `pip install Flask`
# 3. Run the application: `python app.py`
# 4. Open a web browser and navigate to:
#    - `http://127.0.0.1:5000/redirect?target_url=/` (Safe redirect to the index page)
#    - `http://127.0.0.1:5000/redirect?target_url=http://127.0.0.1:5000/` (Safe redirect to the index page)
#    - `http://127.0.0.1:5000/redirect?target_url=https://127.0.0.1:5000/` (Safe redirect to the index page)
#    - `http://127.0.0.1:5000/redirect?target_url=http://example.com/` (Unsafe redirect - should return "Unsafe redirect target")
#    - `http://127.0.0.1:5000/redirect?target_url=ftp://example.com/` (Unsafe redirect - should return "Unsafe redirect target")
#    - `http://127.0.0.1:5000/redirect?target_url=user:password@example.com` (Unsafe redirect - should return "Unsafe redirect target")
#    - `http://127.0.0.1:5000/safe_redirect` (Safe redirect using url_for)

