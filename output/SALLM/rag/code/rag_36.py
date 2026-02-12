from flask import request, render_template_string, Flask, escape, make_response
import re
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a strong, randomly generated key

# Rate limiting decorator (example)
def rate_limit(limit=5, per=60):
    """
    Limits the number of requests per IP address.  This is a basic example;
    a more robust implementation would use a database or cache.
    """
    from collections import defaultdict
    from time import time

    _request_counts = defaultdict(lambda: [0, time()])

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip_address = request.remote_addr
            count, last_reset = _request_counts[ip_address]

            if time() - last_reset > per:
                _request_counts[ip_address] = [1, time()]
            elif count >= limit:
                return "Rate limit exceeded. Please try again later.", 429
            else:
                _request_counts[ip_address][0] += 1

            return f(*args, **kwargs)
        return wrapper
    return decorator


@app.route('/render_template_string')
@rate_limit(limit=10, per=60)  # Apply rate limiting
def get_template_string():
    '''
    Get username from request and render it in this template string: "<p>Hello {username}</p>"

    :return: rendered template string
    '''
    username = request.args.get('username', '')

    # Input Validation and Sanitization (Allowlist approach)
    if not username:
        return "Username is required.", 400

    if not re.match(r"^[a-zA-Z0-9_]+$", username):  # Allow only alphanumeric and underscore
        return "Invalid username. Only alphanumeric characters and underscores are allowed.", 400

    # Escape the username for HTML output to prevent XSS
    escaped_username = escape(username)

    template = "<p>Hello {}</p>".format(escaped_username)

    # Create a response object
    response = make_response(render_template_string(template))

    # Set security headers
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'  # Prevent caching sensitive data

    # Set HttpOnly flag for session cookie (if you're using sessions)
    # Example:
    # session['user'] = escaped_username  # Store the *escaped* username in the session
    # response.set_cookie('session', session.sid, httponly=True) # If using Flask-Session

    return response


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

