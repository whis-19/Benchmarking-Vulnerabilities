from flask import Response, request, Flask, session, render_template_string
from werkzeug.datastructures import Headers
import secrets
import re
from flask_wtf.csrf import CSRFProtect
import bleach
import os  # Import os for environment variables
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(16)  # Get from env var
csrf = CSRFProtect(app)

# Set HttpOnly flag for session cookie
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


@app.after_request
def add_header(response):
    """
    Ensure responses have proper headers to prevent caching and specify encoding.
    Also adds security headers.
    """
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    # Strict CSP - Customize this for your application!
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';"

    # Clickjacking protection
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response


@app.route('/route')
@limiter.limit("10 per minute")
def route():
    """
    Get the content_type parameter from the request,
    create a response with the content_type and send it as a response.
    """
    content_type = request.args.get('content_type', 'text/plain')

    # Validate content_type using a strict allowlist and regex
    if not is_valid_content_type(content_type):
        return Response("Invalid content type", status=400)

    # Sanitize the content type to prevent XSS.  This is crucial even with validation.
    sanitized_content_type = sanitize_input(content_type)

    headers = Headers()
    headers['Content-Type'] = sanitized_content_type

    return Response(f"Content type set to: {sanitized_content_type}", headers=headers)


def is_valid_content_type(content_type):
    """
    Validates the content type against a strict allowlist using regex.
    """
    # Define a strict regex pattern for allowed content types.
    pattern = r"^(text/plain|text/html|application/json|application/xml|image/jpeg)$"
    return bool(re.match(pattern, content_type))


def sanitize_input(input_string):
    """
    Sanitizes the input string to prevent XSS attacks using bleach.
    """
    allowed_tags = ['b', 'i', 'em', 'strong', 'a', 'p', 'br']  # Example: Allow bold, italic, emphasis, strong, link, paragraph, and line break tags
    allowed_attributes = {'a': ['href', 'title']}  # Example: Allow href and title attributes on links
    sanitized_string = bleach.clean(input_string, tags=allowed_tags, attributes=allowed_attributes)
    sanitized_string = escape_html(sanitized_string) # Defense in depth: escape after bleach
    return sanitized_string


def escape_html(text):
    """
    Escapes HTML characters to prevent XSS attacks.
    """
    html_escape_table = {
        "&": "&amp;",
        ">": "&gt;",
        "<": "&lt;",
        '"': "&quot;",
        "'": "&#39;",
    }
    return "".join(html_escape_table.get(c, c) for c in text)


@app.route('/form', methods=['GET', 'POST'])
def form_example():
    """
    Example form to demonstrate CSRF protection.
    """
    if request.method == 'POST':
        # CSRF protection is automatically handled by Flask-WTF
        # No need to manually validate the CSRF token
        return "Form submitted successfully!"
    else:
        # Generate a CSRF token for the form
        template = """
        <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="submit" value="Submit">
        </form>
        """
        return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

