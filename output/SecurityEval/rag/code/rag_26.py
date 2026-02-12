from flask import Response, request, Flask, session
from werkzeug.datastructures import Headers
import secrets
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a strong secret key

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


@app.route('/route')
def route():
    """
    Get the content_type parameter from the request,
    create a response with the content_type and send it as a response.
    """
    content_type = request.args.get('content_type', default='text/plain')

    # Input Validation:  Strict allowlist for content_type
    allowed_content_types = ['text/plain', 'application/json', 'text/html', 'application/xml']  # Define allowed types
    if content_type not in allowed_content_types:
        return Response("Invalid content type", status=400)  # Return a 400 Bad Request error

    # Encoding specification
    headers = Headers()
    headers.add('Content-Type', f'{content_type}; charset=utf-8')

    # Create the response
    response = Response("Response with specified content type", headers=headers)

    # Set HttpOnly flag for session cookie (if sessions are used)
    session.permanent = True  # Make the session "permanent" across restarts
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS

    return response


@app.route('/form', methods=['GET', 'POST'])
def form_example():
    """
    Example form with CSRF protection using a nonce.
    """
    if request.method == 'GET':
        nonce = secrets.token_hex(16)  # Generate a unique nonce
        session['csrf_token'] = nonce
        return f'''
            <form method="POST">
                <input type="text" name="data">
                <input type="hidden" name="csrf_token" value="{nonce}">
                <button type="submit">Submit</button>
            </form>
        '''
    elif request.method == 'POST':
        user_data = request.form.get('data')
        csrf_token = request.form.get('csrf_token')

        if csrf_token != session.get('csrf_token'):
            return Response("CSRF token invalid", status=400)

        # Process the user data (sanitize and validate!)
        sanitized_data = html.escape(user_data) # Prevent XSS

        # Remove the CSRF token from the session after validation
        session.pop('csrf_token', None)

        return f"Data received: {sanitized_data}"

import html

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

