from flask import Flask, request, make_response, escape, session
import os
import secrets
from functools import wraps
import time
import re  # Import the regular expression module
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def limit_requests(limit=5, period=60):
    """Limits the number of requests a user can make within a given period.

    Args:
        limit: The maximum number of requests allowed.
        period: The time period (in seconds) during which the limit applies.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # IP-based rate limiting (simplified example - consider using a library for production)
            ip_address = request.remote_addr
            if 'rate_limits' not in session:
                session['rate_limits'] = {}

            if ip_address not in session['rate_limits']:
                session['rate_limits'][ip_address] = {'request_count': 0, 'request_time': time.time()}

            elapsed_time = time.time() - session['rate_limits'][ip_address]['request_time']
            if elapsed_time > period:
                session['rate_limits'][ip_address]['request_count'] = 0
                session['rate_limits'][ip_address]['request_time'] = time.time()

            if session['rate_limits'][ip_address]['request_count'] >= limit:
                logging.warning(f"Rate limit exceeded for IP: {ip_address}")
                return "Too many requests. Please try again later.", 429

            session['rate_limits'][ip_address]['request_count'] += 1
            session.modified = True

            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route("/profile")
@limit_requests(limit=5, period=60)
def profile():
    """
    Get the username from the request, make a response with it and return it.
    """
    username = request.args.get('username')

    if username:
        # Improved Input Validation
        if not isinstance(username, str):
            logging.warning("Invalid username: Not a string")
            return "Invalid username: Must be a string", 400

        if len(username) > 100:
            logging.warning("Invalid username: Too long")
            return "Invalid username: Too long", 400

        # Whitelist allowed characters (alphanumeric and underscores)
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            logging.warning("Invalid username: Illegal characters")
            return "Invalid username: Only alphanumeric characters and underscores allowed", 400

        escaped_username = escape(username)
        response_html = f"<h1>Profile</h1><p>Username: {escaped_username}</p>"
        response = make_response(response_html)

        # More specific CSP
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self';"
        return response
    else:
        return "<h1>Profile</h1><p>No username provided.</p>"


# CSRF protection (example - needs adaptation for forms)
@app.route('/form', methods=['GET', 'POST'])
def form_example():
    if request.method == 'GET':
        session['csrf_token'] = secrets.token_hex(16)
        return f'''
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{session['csrf_token']}">
            <input type="text" name="data">
            <button type="submit">Submit</button>
        </form>
        '''
    elif request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        if csrf_token != session.pop('csrf_token', None):
            logging.warning("CSRF token invalid")
            return "CSRF token invalid", 400

        data = escape(request.form.get('data', '')) # Escape user input
        return f"Data received: {data}"


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))

