import requests
from flask import Flask, request, make_response, session
import os
import re
import secrets
from urllib.parse import urlparse
import logging
import socket
import ipaddress

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a cryptographically strong secret key

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting (example - implement a more robust solution in production)
RATE_LIMIT = 10
REQUEST_COUNT = {}

# Create a requests session with restricted protocols
session_obj = requests.Session()
adapter = requests.adapters.HTTPAdapter(max_retries=3)  # Add retries
session_obj.mount('http://', adapter)
session_obj.mount('https://', adapter)

# Disable file:// and other potentially dangerous protocols
# This is a defense-in-depth measure against SSRF
class BlockedSchemeAdapter(requests.adapters.HTTPAdapter):
    def send(self, request, **kwargs):
        if request.url.lower().startswith("file://"):
            raise requests.exceptions.InvalidSchema("File protocol is blocked")
        return super().send(request, **kwargs)

session_obj.mount("file://", BlockedSchemeAdapter())
session_obj.mount("gopher://", BlockedSchemeAdapter())  # Example: Block gopher

def is_valid_user_id(user_id):
    """
    Validates the user_id to prevent injection attacks.
    Allows only alphanumeric characters and underscores, with a length limit.
    """
    pattern = r"^[a-zA-Z0-9_]{1,32}$"  # Added length limit of 1-32 characters
    return bool(re.match(pattern, user_id))

def is_valid_url(url):
    """
    Validates the URL to prevent Server-Side Request Forgery (SSRF).
    Checks if the hostname is a valid and safe domain.
    """
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc, is_safe_domain(result.netloc)])
    except:
        logging.warning(f"Invalid URL format: {url}")
        return False

def is_safe_domain(hostname):
    """
    Checks if the hostname is in a list of allowed domains.
    Also mitigates DNS rebinding attacks by resolving the hostname to an IP address
    and checking if the IP address is in a safe range.
    """
    allowed_domains = ['api.github.com']  # Only allow requests to GitHub API
    if hostname not in allowed_domains:
        return False

    try:
        ip_address = socket.gethostbyname(hostname)
        # Define a safe IP range (e.g., public IP ranges)
        # Adjust this range based on your specific requirements
        if not is_safe_ip(ip_address):
            logging.warning(f"Unsafe IP address resolved for hostname {hostname}: {ip_address}")
            return False
        return True
    except socket.gaierror:
        logging.warning(f"Could not resolve hostname: {hostname}")
        return False

def is_safe_ip(ip_address):
    """
    Checks if the IP address is within a safe range.
    """
    try:
        ip = ipaddress.ip_address(ip_address)

        # Block private and reserved IP ranges
        if ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local:
            return False

        # Block cloud metadata endpoints (example - adjust as needed)
        if str(ip).startswith("169.254.169.254"):
            return False

        # Example: Allow only public IP addresses (not private or reserved ranges)
        # This is a simplified example and may not be suitable for all environments.
        socket.inet_aton(ip_address)  # Validate IP address format
        # Add more sophisticated checks here based on your network configuration
        # For example, check if the IP address is within a specific CIDR block
        return True
    except ValueError:
        return False

def rate_limit_exceeded(ip_address):
    """
    Basic rate limiting to prevent abuse.  A production system would use a more robust
    rate limiting mechanism (e.g., Redis, Memcached).
    """
    if ip_address not in REQUEST_COUNT:
        REQUEST_COUNT[ip_address] = 0
    REQUEST_COUNT[ip_address] += 1
    if REQUEST_COUNT[ip_address] > RATE_LIMIT:
        logging.warning(f"Rate limit exceeded for IP: {ip_address}")
        return True
    return False

@app.route("/user")
def retrieve_info():
    """
    Retrieves user info from GitHub using the GitHub's API.
    """
    ip_address = request.remote_addr

    if rate_limit_exceeded(ip_address):
        return "Rate limit exceeded. Please try again later.", 429

    user_id = request.args.get("user_id")

    if not user_id:
        logging.warning(f"Missing user_id parameter from IP: {ip_address}")
        return "Missing user_id parameter", 400

    if not is_valid_user_id(user_id):
        logging.warning(f"Invalid user_id format: {user_id} from IP: {ip_address}")
        return "Invalid user_id format. Only alphanumeric characters and underscores are allowed.", 400

    github_api_url = f"https://api.github.com/users/{user_id}"

    if not is_valid_url(github_api_url):
        logging.warning(f"Invalid or unsafe URL: {github_api_url} from IP: {ip_address}")
        return "Invalid or unsafe URL", 400

    try:
        response = session_obj.get(github_api_url)  # Use the session object
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        user_info = response.json()

        # Create a response object
        resp = make_response(user_info)
        resp.headers['Content-Type'] = 'application/json; charset=utf-8'  # Specify encoding
        resp.headers['X-Content-Type-Options'] = 'nosniff' #Prevent MIME sniffing
        resp.headers['X-Frame-Options'] = 'DENY' #Prevent Clickjacking
        resp.headers['Content-Security-Policy'] = "default-src 'self'" #Prevent Cross-Site Scripting (XSS)

        # Cookie settings (example)
        session.permanent = True
        app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

        # Regenerate session ID after authentication (example - not strictly authentication here, but good practice)
        session.regenerate()

        return resp

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching data from GitHub for user_id {user_id} from IP {ip_address}: {e}")
        return f"Error fetching data from GitHub: {e}", 500
    except ValueError:
        logging.error(f"Invalid JSON response from GitHub for user_id {user_id} from IP {ip_address}")
        return "Invalid JSON response from GitHub", 500
    except socket.gaierror as e:
        logging.error(f"DNS resolution error for user_id {user_id} from IP {ip_address}: {e}")
        return "DNS resolution error", 500

    finally:
        # Clean up request count after a certain period (example)
        # In a real application, use a background task or scheduled job
        # to periodically clear the REQUEST_COUNT dictionary.
        pass

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to every response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # response.headers['X-Frame-Options'] = 'DENY' # Replaced with CSP
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none';" # More restrictive CSP and clickjacking protection
    # response.headers['X-XSS-Protection'] = '1; mode=block' # Deprecated
    return response

# Example of a more robust rate limiting (not implemented fully)
# Requires a persistent store like Redis
# import redis
# redis_client = redis.Redis(host='localhost', port=6379, db=0)

# def is_rate_limited(user_id, endpoint, limit, period):
#     key = f"rate_limit:{user_id}:{endpoint}"
#     count = redis_client.incr(key)
#     if count == 1:
#         redis_client.expire(key, period)  # Set expiration time
#     return count > limit

# Example usage (would replace the existing rate_limit_exceeded function)
# if is_rate_limited(user_id, request.path, 100, 60): # 100 requests per minute
#     return "Rate limit exceeded", 429

if __name__ == "__main__":
    app.run(debug=True)

