import re
from urllib.parse import urlparse
from flask import Flask, request, redirect, render_template, make_response
import secrets
import functools

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generate a random secret key

# Regular expression to match URLs containing example.com
ALLOWED_HOST = r'example\.com'

def generate_csrf_token():
    """Generates a CSRF token."""
    return secrets.token_hex(16)

def set_csrf_cookie(response):
    """Sets the CSRF cookie in the response."""
    csrf_token = generate_csrf_token()
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure, HttpOnly, and Strict SameSite
    return csrf_token

def verify_csrf_token(request):
    """Verifies the CSRF token from the cookie and the form data."""
    cookie_token = request.cookies.get('csrf_token')
    form_token = request.form.get('csrf_token')

    if not cookie_token or not form_token or cookie_token != form_token:
        return False
    return True

def csrf_protected(fn):
    """Decorator to protect routes against CSRF attacks."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == 'POST':
            if not verify_csrf_token(request):
                return "CSRF token verification failed.", 400  # Or redirect to an error page
        return fn(*args, **kwargs)
    return wrapper

@app.route('/')
def index():
    """Renders the index page with a CSRF token."""
    response = make_response(render_template('index.html', csrf_token=generate_csrf_token()))
    set_csrf_cookie(response)
    return response

@app.route('/redirect', methods=['POST'])
@csrf_protected
def redirect_target():
    """
    Redirects to the target URL if it matches the allowed pattern.
    Otherwise, redirects to the index page.
    """
    target = request.form.get('target')

    if not target:
        return "Target URL is missing.", 400

    try:
        parsed_url = urlparse(target)
        if not parsed_url.netloc:  # Check if netloc is empty (relative URL)
            return "Invalid URL: Missing hostname.", 400

        if re.search(ALLOWED_HOST, parsed_url.netloc):
            return redirect(target)
        else:
            return redirect("/")  # Redirect to home if not allowed

    except Exception as e:
        print(f"Error parsing URL: {e}")
        return "Invalid URL.", 400

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=443, ssl_context='adhoc') #HTTPS enabled

