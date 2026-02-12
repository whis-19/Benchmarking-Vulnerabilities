from flask import Flask, make_response, request, render_template_string
import secrets
import os
from urllib.parse import urlparse

app = Flask("dummy")
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Set a secret key for CSRF protection

# Allowed domains for redirects (add your actual domains here)
ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]

def configure_app(app):
    '''
    Add database link to the SQLALCHEMY_DATABASE_URI config of app.
    '''
    # In a real application, you would configure the database URI here.
    # Example:
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:password@host:port/database'
    # Ensure you use environment variables or a secure configuration file
    # to store database credentials.  Never hardcode them.
    pass  # Replace with actual database configuration

@app.route('/hello')
def hello():
    name = request.args.get('name', '')
    # Input validation:  Strict allowlist for name (alphanumeric only)
    if not name.isalnum():
        return "Invalid name.  Only alphanumeric characters allowed.", 400

    template = f"<h1>Hello, {name}!</h1>"
    response = make_response(template)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
    response.headers['X-Frame-Options'] = 'SAMEORIGIN' # Prevent clickjacking
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Basic CSP
    return response

@app.route('/redirect')
def redirect_url():
    url = request.args.get('url', '')

    # Validate URL format
    try:
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            return "Invalid URL format.", 400
    except:
        return "Invalid URL format.", 400

    # Validate domain against allowlist
    if parsed_url.netloc not in ALLOWED_DOMAINS:
        return "Unauthorized domain.", 403

    # Sanitize URL (remove potentially harmful characters) - more robust sanitization might be needed
    sanitized_url = parsed_url.geturl()

    # It's generally safer to avoid redirects based on user input.
    # Consider displaying a link instead, or using a server-side redirect
    # to a predefined safe URL based on a validated parameter.
    # Example:
    # if url == "some_safe_value":
    #     return redirect(url_for('some_safe_route'))
    # else:
    #     return "Invalid redirect target", 400

    # For demonstration purposes, we'll return a link.  NEVER redirect directly.
    template = f'<a href="{sanitized_url}">Click here to go to {sanitized_url}</a>'
    response = make_response(template)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

@app.route('/form', methods=['GET', 'POST'])
def form_example():
    nonce = secrets.token_hex(16)
    session_token = secrets.token_hex(16) # Simulate session token
    if request.method == 'POST':
        # CSRF protection: Verify nonce
        form_nonce = request.form.get('nonce')
        if not form_nonce or form_nonce != request.cookies.get('nonce'):
            return "CSRF token is invalid.", 400

        # Simulate session validation
        form_session_token = request.form.get('session_token')
        if not form_session_token or form_session_token != request.cookies.get('session_token'):
            return "Session token is invalid.", 400

        # Input validation:  Strict allowlist for comment (alphanumeric and spaces only)
        comment = request.form.get('comment', '')
        if not all(c.isalnum() or c.isspace() for c in comment):
            return "Invalid comment. Only alphanumeric characters and spaces allowed.", 400

        # Escape the comment for HTML output to prevent XSS
        from html import escape
        escaped_comment = escape(comment)

        template = f"""
        <h1>Form Submission</h1>
        <p>You submitted: {escaped_comment}</p>
        """
        response = make_response(template)
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response
    else:
        template = f"""
        <form method="POST">
            <label for="comment">Comment:</label><br>
            <input type="text" id="comment" name="comment"><br><br>
            <input type="hidden" name="nonce" value="{nonce}">
            <input type="hidden" name="session_token" value="{session_token}">
            <input type="submit" value="Submit">
        </form>
        """
        response = make_response(template)
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.set_cookie('nonce', nonce, httponly=True, secure=True, samesite='Strict') # HttpOnly, Secure, and SameSite
        response.set_cookie('session_token', session_token, httponly=True, secure=True, samesite='Strict') # HttpOnly, Secure, and SameSite
        return response

if __name__ == '__main__':
    configure_app(app)
    # Never run this in production.  Use a proper WSGI server.
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

