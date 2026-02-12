from flask import request, Response, Flask, session
import re
import os
from hashlib import sha256

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

# Rate limiting (example - adjust as needed)
REQUEST_LIMIT = 10
REQUEST_WINDOW = 60  # seconds
user_request_counts = {}


def is_rate_limited(user_ip):
    """Checks if a user has exceeded the request limit."""
    import time
    now = time.time()
    if user_ip not in user_request_counts:
        user_request_counts[user_ip] = []

    # Remove requests older than the window
    user_request_counts[user_ip] = [
        ts for ts in user_request_counts[user_ip] if ts > now - REQUEST_WINDOW
    ]

    if len(user_request_counts[user_ip]) >= REQUEST_LIMIT:
        return True

    user_request_counts[user_ip].append(now)
    return False


@app.after_request
def add_security_headers(response):
    """Adds security headers to the response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    return response


@app.route('/get_average_score', methods=['GET'])  # Use GET for idempotent operations
def get_average_score():
    """
    Get total score and total count from the request using 'total_score' and 'total_count' and return average score.
    """
    user_ip = request.remote_addr
    if is_rate_limited(user_ip):
        return Response("Rate limit exceeded. Please try again later.", status=429)

    total_score_str = request.args.get('total_score')
    total_count_str = request.args.get('total_count')

    # Input Validation using allowlist and regex
    if not (total_score_str and total_count_str):
        return Response("Missing total_score or total_count parameters.", status=400)

    if not (re.match(r"^[0-9]+(\.[0-9]+)?$", total_score_str) and re.match(r"^[0-9]+$", total_count_str)):
        return Response("Invalid input format. total_score must be a number and total_count must be an integer.", status=400)

    try:
        total_score = float(total_score_str)
        total_count = int(total_count_str)
    except ValueError:
        return Response("Invalid input. Could not convert to number.", status=400)

    if total_count == 0:
        return Response("Total count cannot be zero.", status=400)

    average_score = total_score / total_count

    return Response(f"Average score: {average_score}", status=200)


# Double-submitted cookie example (simplified)
@app.route('/set_token')
def set_token():
    """Sets a token in a cookie and returns it for use in a form."""
    token = sha256(os.urandom(32)).hexdigest()
    session['csrf_token'] = token  # Store server-side
    resp = Response(f"Token set.  Use this token in your form: {token}")
    resp.set_cookie('csrf_token', token, httponly=True, samesite='Strict')  # HttpOnly and SameSite
    return resp


@app.route('/submit_form', methods=['POST'])
def submit_form():
    """Handles form submission with CSRF protection."""
    form_token = request.form.get('csrf_token')
    session_token = session.get('csrf_token')

    if not form_token or not session_token or form_token != session_token:
        return Response("CSRF token validation failed.", status=400)

    # Process the form data (after successful validation)
    data = request.form.get('data')  # Example form field

    # Sanitize data before processing (example)
    if data:
        data = data.replace("<", "&lt;").replace(">", "&gt;")

    return Response(f"Form submitted successfully. Data: {data}", status=200)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

