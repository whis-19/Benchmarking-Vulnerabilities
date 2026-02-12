from flask import Flask, request, redirect, session
from urllib.parse import urlparse
import os
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a random secret key

@app.after_request
def add_header(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Content-Type'] = 'text/html; charset=utf-8' # Specify encoding
    return response

@app.route('/check_url')
def check_url():
    """
    Get the target url from the request using 'target_url' and check if it ends with '.com/'. 
    If it does, return 'True', otherwise, return 'False'.
    """
    target_url = request.args.get('target_url', '')

    if not target_url:
        return "False"  # Or handle the missing parameter appropriately

    try:
        parsed_url = urlparse(target_url)

        # Validate the scheme (e.g., http, https)
        if parsed_url.scheme not in ['http', 'https']:
            return "False"  # Invalid scheme

        # Check if the netloc (host) ends with '.com' and the path ends with '/'
        if parsed_url.netloc.endswith('.com') and parsed_url.path.endswith('/'):
            return "True"
        else:
            return "False"

    except Exception as e:
        # Log the error for debugging purposes (important in production)
        print(f"Error parsing URL: {e}")
        return "False"  # Handle parsing errors gracefully

# Double-submitted cookie protection example (simplified)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # In a real application, you would validate the username and password
        # against a database or other authentication system.

        if username == 'test' and password == 'password':  # Example credentials
            # Generate a CSRF token
            csrf_token = secrets.token_hex(16)

            # Store the CSRF token in the session
            session['csrf_token'] = csrf_token

            # Set the CSRF token as a cookie (HttpOnly)
            response = redirect('/protected')
            response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict') # Secure and SameSite attributes
            return response
        else:
            return "Login failed"

    return '''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <button type="submit">Login</button>
        </form>
    '''

@app.route('/protected')
def protected():
    # Verify the CSRF token
    csrf_token_cookie = request.cookies.get('csrf_token')
    csrf_token_session = session.get('csrf_token')

    if not csrf_token_cookie or not csrf_token_session or csrf_token_cookie != csrf_token_session:
        return "CSRF token validation failed"

    return "Protected resource accessed successfully!"

if __name__ == '__main__':
    # Never run in production with debug=True
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

