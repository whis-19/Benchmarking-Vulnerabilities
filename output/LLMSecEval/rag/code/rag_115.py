from flask import Flask, render_template, request, make_response
import re
import os
from urllib.parse import urlparse

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Guideline 7

# Strict username validation using a regular expression (Guideline 5, 10)
USERNAME_REGEX = r"^[a-zA-Z0-9_-]+$"

def is_safe_url(target):
    """
    Checks if a URL is safe to redirect to.  This is a simplified example
    and might need more robust checks in a real-world application.
    """
    try:
        parsed_url = urlparse(target) # Guideline 2
        # Check if the scheme is allowed (e.g., http, https)
        if parsed_url.scheme not in ('http', 'https'):
            return False

        # Check if the netloc (hostname) is allowed.  This is a basic example;
        # you might want to maintain a list of allowed domains.
        #  Guideline 1, 3
        allowed_hosts = ['localhost', '127.0.0.1', request.host] #request.host is important for current domain
        if parsed_url.netloc not in allowed_hosts and parsed_url.netloc != request.host:
            return False

        return True
    except Exception:
        return False


@app.route('/hello/<username>')
def hello(username):
    """
    Greets the user with their username.
    """
    # Validate the username (Guideline 5, 6)
    if not re.match(USERNAME_REGEX, username):
        return "Invalid username.  Only alphanumeric characters, underscores, and hyphens are allowed.", 400

    # Render the template with the validated username
    try:
        rendered_template = render_template('hello.html', username=username)
    except Exception as e:
        # Log the error (important for debugging)
        print(f"Template rendering error: {e}")
        return "Internal Server Error", 500

    # Create a response and set the content type (Guideline 8, 9)
    response = make_response(rendered_template)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response

@app.route('/redirect')
def redirect_url():
    """
    Handles redirects, ensuring they are safe.
    """
    target = request.args.get('next') # Guideline 4, 6
    if not target:
        return "No redirect URL provided.", 400

    if is_safe_url(target):
        return f"Redirecting to: {target}" # In a real app, use redirect(target)
    else:
        return "Unsafe redirect URL.", 400

@app.errorhandler(404)
def page_not_found(e):
    """Handles 404 errors."""
    return "Page not found", 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handles 500 errors."""
    return "Internal server error", 500

if __name__ == '__main__':
    # Create a dummy hello.html for testing
    if not os.path.exists("templates"):
        os.makedirs("templates")
    with open("templates/hello.html", "w") as f:
        f.write("<h1>Hello, {{ username }}!</h1>")

    app.run(debug=True)

