from flask import Flask, request, make_response, escape, session
import os
import secrets
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a random secret key

# Rate limiting decorator
def limit_requests(limit=5, period=60):
    """Limits the number of requests a user can make within a given period.

    Args:
        limit: The maximum number of requests allowed.
        period: The time period (in seconds) during which the limit applies.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'request_count' not in session:
                session['request_count'] = 0
                session['last_request'] = 0
            
            import time
            now = time.time()
            if now - session['last_request'] > period:
                session['request_count'] = 0

            if session['request_count'] >= limit:
                return "Too many requests. Please try again later.", 429

            session['request_count'] += 1
            session['last_request'] = now
            session.modified = True  # Ensure session is saved

            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route("/profile")
@limit_requests(limit=10, period=60)  # Example: Limit to 10 requests per minute
def profile():
    """
    Get the username from the request, make a response with it and return it.
    Escapes the username to prevent XSS vulnerabilities.
    """
    username = request.args.get('username')
    if username:
        escaped_username = escape(username)  # Escape the username
        response_text = f"<h1>Hello, {escaped_username}!</h1>"
        response = make_response(response_text)
        return response
    else:
        return "Please provide a username in the query string (e.g., /profile?username=yourname)", 400


@app.route("/form", methods=['GET', 'POST'])
def form():
    """
    Handles a simple form submission with CSRF protection using a nonce.
    """
    if request.method == 'GET':
        nonce = secrets.token_hex(16)
        session['csrf_token'] = nonce
        return f"""
            <form method="POST">
                <label for="data">Enter some data:</label><br>
                <input type="text" id="data" name="data"><br><br>
                <input type="hidden" name="csrf_token" value="{nonce}">
                <input type="submit" value="Submit">
            </form>
        """
    elif request.method == 'POST':
        user_data = request.form.get('data')
        csrf_token = request.form.get('csrf_token')

        if not csrf_token or csrf_token != session.get('csrf_token'):
            return "CSRF token is invalid!", 400

        # Process the user data (escape it before displaying)
        escaped_data = escape(user_data)
        return f"You submitted: {escaped_data}"
    else:
        return "Method not allowed", 405


if __name__ == '__main__':
    #  Do NOT use debug=True in production!
    #  Instead, use a production WSGI server like gunicorn or uWSGI.
    #  Example: gunicorn --bind 0.0.0.0:8000 your_app:app
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 8000)))

