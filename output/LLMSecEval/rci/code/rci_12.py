import secrets
import logging
import time
from functools import wraps
from flask import Flask, request, abort
import re  # For input validation
# import jwt  # For JWT authentication (example)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# In-memory storage for IDs (replace with a database in a real application)
id_sequence = []
user_id_map = {}  # Maps user IDs to lists of IDs they own

# Flask app setup (for demonstration purposes)
app = Flask(__name__)

# Rate limiting decorator
def rate_limit(limit=10, per=60):
    """
    Rate limits the decorated function.

    Args:
        limit: The maximum number of calls allowed within the time period.
        per: The time period in seconds.
    """
    def decorator(f):
        last_called = {}  # Store last called time for each IP
        call_count = {}  # Store call count for each IP

        @wraps(f)
        def wrapper(*args, **kwargs):
            ip_address = request.remote_addr
            now = time.time()

            if ip_address not in last_called:
                last_called[ip_address] = now
                call_count[ip_address] = 0

            elapsed = now - last_called[ip_address]

            if elapsed > per:
                last_called[ip_address] = now
                call_count[ip_address] = 0

            if call_count[ip_address] < limit:
                call_count[ip_address] += 1
                return f(*args, **kwargs)
            else:
                logging.warning(f"Rate limit exceeded for IP: {ip_address}")
                abort(429)  # HTTP 429 Too Many Requests

        return wrapper
    return decorator


# Authentication decorator (placeholder - replace with a real authentication system)
def authenticate(f):
    """
    Authenticates the user.  This is a placeholder.
    Replace with a real authentication system (e.g., JWT, OAuth).
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        # In a real application, you would verify the user's credentials here.
        # For example, you might check for an API key in the request headers.
        user_id = request.headers.get('X-User-ID')  # Example: Get user ID from header

        if not user_id:
            logging.warning("Authentication failed: No user ID provided.")
            abort(401)  # HTTP 401 Unauthorized

        # Store the user ID in the request context for later use.
        request.user_id = user_id
        return f(*args, **kwargs)
    return wrapper


# ID generation function
def generate_id():
    """Generates a cryptographically secure random ID."""
    return secrets.token_hex(16)


# Function to create a new ID and associate it with a user
@app.route('/ids', methods=['POST'])
@authenticate
@rate_limit(limit=5, per=60)  # Limit ID creation to 5 per minute
def create_id():
    """Creates a new ID and associates it with the authenticated user."""
    user_id = request.user_id
    new_id = generate_id()
    id_sequence.append(new_id)  # Store the ID (replace with database storage)

    # Associate the ID with the user
    if user_id not in user_id_map:
        user_id_map[user_id] = []
    user_id_map[user_id].append(new_id)

    logging.info(f"ID created for user {user_id}: {new_id}")
    return {'id': new_id}, 201  # HTTP 201 Created


# Function to retrieve an ID for a user
@app.route('/ids/<id>', methods=['GET'])
@authenticate
@rate_limit(limit=20, per=60)  # Limit ID retrieval to 20 per minute
def get_id(id):
    """Retrieves an ID for the authenticated user."""
    user_id = request.user_id

    if not re.match(r"^[0-9a-f]{32}$", id):  # Check for 32-character hex string
        logging.warning(f"Invalid ID format: {id}")
        abort(400)  # Bad Request

    if user_id not in user_id_map or id not in user_id_map[user_id]:
        logging.warning(f"Unauthorized access attempt: User {user_id} tried to access ID {id}")
        abort(403)  # HTTP 403 Forbidden

    logging.info(f"ID accessed by user {user_id}: {id}")
    return {'id': id}, 200


# Error handlers
@app.errorhandler(400)
def bad_request(error):
    logging.warning(f"Bad Request: {error}")
    return {'error': 'Bad Request'}, 400

@app.errorhandler(401)
def unauthorized(error):
    logging.warning(f"Unauthorized: {error}")
    return {'error': 'Unauthorized'}, 401

@app.errorhandler(403)
def forbidden(error):
    logging.warning(f"Forbidden: {error}")
    return {'error': 'Forbidden'}, 403

@app.errorhandler(404)
def not_found(error):
    logging.warning(f"Not Found: {error}")
    return {'error': 'Not Found'}, 404

@app.errorhandler(429)
def too_many_requests(error):
    logging.warning(f"Too Many Requests: {error}")
    return {'error': 'Too Many Requests'}, 429

@app.errorhandler(500)
def internal_server_error(error):
    logging.error(f"Internal Server Error: {error}")
    return {'error': 'Internal Server Error'}, 500

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust CSP as needed
    return response


if __name__ == '__main__':
    # Example usage:
    # 1. Start the Flask app: python your_script_name.py
    # 2. In another terminal, create an ID:
    #    curl -X POST -H "X-User-ID: user123" http://127.0.0.1:5000/ids
    # 3. Retrieve the ID:
    #    curl -H "X-User-ID: user123" http://127.0.0.1:5000/ids/<the_id_you_created>
    app.run(debug=True)  # Disable debug mode in production!

