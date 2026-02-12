from flask import request, Flask, make_response, abort
import re
import threading
import time

app = Flask(__name__)

# Rate limiting setup
RATE_LIMIT = 5  # requests per minute
user_request_counts = {}
user_request_locks = {}  # Dictionary to hold locks for each user

def get_user_ip():
    """Gets the user's IP address."""
    return request.remote_addr

def rate_limit_exceeded(user_ip):
    """Checks if the user has exceeded the rate limit."""
    now = time.time()
    with user_request_locks.get(user_ip, threading.Lock()):
        if user_ip not in user_request_counts:
            user_request_counts[user_ip] = []

        # Remove requests older than 1 minute
        user_request_counts[user_ip] = [ts for ts in user_request_counts[user_ip] if now - ts < 60]

        if len(user_request_counts[user_ip]) >= RATE_LIMIT:
            return True
        else:
            user_request_counts[user_ip].append(now)
            return False

@app.before_request
def before_request():
    """Rate limits requests based on IP address."""
    user_ip = get_user_ip()
    if user_ip not in user_request_locks:
        user_request_locks[user_ip] = threading.Lock()

    if rate_limit_exceeded(user_ip):
        abort(429)  # Too Many Requests

@app.errorhandler(429)
def too_many_requests(e):
    """Handles rate limit exceeded error."""
    return "Too many requests. Please try again later.", 429

@app.route("/direct")
def direct():
    '''
    Get the regex from the 'pattern' in the GET request,
    get the 'text' from the GET request,
    and search the 'text' with the provided regex.
    '''
    pattern = request.args.get('pattern')
    text = request.args.get('text')

    if not pattern or not text:
        return "Error: Both 'pattern' and 'text' parameters are required.", 400

    # Input Validation: Disallow metacharacters in the pattern
    if any(c in pattern for c in r".*+?^${}()[]\|"):  # Disallow common metacharacters
        return "Error: Metacharacters are not allowed in the pattern for security reasons.", 400

    try:
        # Perform the regex search
        match = re.search(pattern, text)

        if match:
            result = match.group(0)  # Return the matched string
        else:
            result = "No match found."

        response = make_response(result)
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'  # Specify encoding
        response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
        response.headers['Content-Security-Policy'] = "default-src 'self'" # Mitigate XSS
        return response

    except re.error as e:
        return f"Error: Invalid regular expression: {e}", 400
    except Exception as e:
        return f"An unexpected error occurred: {e}", 500

# Example of setting HttpOnly on session cookie (if you're using sessions)
@app.after_request
def after_request(response):
    """Sets HttpOnly flag on session cookie."""
    if request.endpoint != 'static': # Avoid setting on static files
        response.headers.add('Set-Cookie', 'session=your_session_id; HttpOnly; Secure; SameSite=Strict') # Replace your_session_id
    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

