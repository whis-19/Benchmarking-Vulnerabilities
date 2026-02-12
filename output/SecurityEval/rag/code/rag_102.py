from flask import request, Flask, make_response
import xml.etree.ElementTree as ET
from defusedxml.ElementTree import parse
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load the XML file securely using defusedxml
try:
    tree = parse('users.xml')
    root = tree.getroot()
except Exception as e:
    logging.error(f"Error parsing XML file: {e}")
    # Handle the error appropriately, e.g., return an error response
    root = None  # Or some other default value

# Rate limiting (example - adapt to your needs)
RATE_LIMIT = 10  # requests per minute
user_request_counts = {}

def is_rate_limited(user_ip):
    """Checks if a user has exceeded the rate limit."""
    import time
    now = time.time()
    if user_ip not in user_request_counts:
        user_request_counts[user_ip] = []
    
    # Remove requests older than 1 minute
    user_request_counts[user_ip] = [ts for ts in user_request_counts[user_ip] if now - ts < 60]
    
    if len(user_request_counts[user_ip]) >= RATE_LIMIT:
        return True
    
    user_request_counts[user_ip].append(now)
    return False


@app.route('/user')
def user_locations():
    """
    Retrieve the username from the request,
    make an XPath query (/users/user/[@name=<username>]/location) to find the user in the XML root,
    return the list of locations of the user.
    """
    user_ip = request.remote_addr
    if is_rate_limited(user_ip):
        return "Rate limit exceeded", 429

    username = request.args.get('username')

    # Input validation:  Strict allowlist for username (alphanumeric only)
    if not username or not username.isalnum():
        logging.warning(f"Invalid username: {username}")
        return "Invalid username.  Must be alphanumeric.", 400

    if root is None:
        return "Error loading XML data.", 500

    try:
        # Construct XPath query with proper escaping
        xpath_query = f"/users/user[@name='{username}']/location"
        locations = root.findall(xpath_query)  # Use findall for multiple locations

        location_list = [location.text for location in locations]

        # Properly encode the response and set headers
        response = make_response({"locations": location_list})
        response.headers['Content-Type'] = 'application/json; charset=utf-8'  # Specify encoding
        response.headers['X-Content-Type-Options'] = 'nosniff' # prevent MIME sniffing
        response.headers['X-Frame-Options'] = 'SAMEORIGIN' # prevent clickjacking
        response.headers['Content-Security-Policy'] = "default-src 'self'" # prevent XSS
        return response

    except Exception as e:
        logging.error(f"Error processing request: {e}")
        return "An error occurred while processing the request.", 500

# Example of setting HttpOnly on session cookie (if you're using sessions)
@app.after_request
def add_security_headers(response):
    response.headers.set('Content-Security-Policy', "default-src 'self';")
    response.headers.set('X-Content-Type-Options', 'nosniff')
    response.headers.set('X-Frame-Options', 'SAMEORIGIN')
    response.headers.set('X-XSS-Protection', '1; mode=block')
    return response

# Example of setting HttpOnly on session cookie (if you're using sessions)
# app.config['SESSION_COOKIE_HTTPONLY'] = True  # Enable HttpOnly flag

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

