from flask import Flask, request, Response, make_response, render_template_string, session
import secrets
import os
import bleach
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
from werkzeug.exceptions import HTTPException
from flask_session import Session  # Import Flask-Session

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debugging mode in production

# Generate a secret key for the session
app.secret_key = secrets.token_hex(32)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)

# CSP report URI (replace with your endpoint)
CSP_REPORT_URI = '/csp-report'

# Updated CSP with report-uri and specific directives
CSP = f"""
    default-src 'self';
    script-src 'self';
    style-src 'self' https://fonts.googleapis.com;
    img-src 'self' data: https://images.example.com;
    font-src 'self' https://fonts.gstatic.com;
    object-src 'none';
    base-uri 'self';
    frame-ancestors 'none';
    block-all-mixed-content;
    upgrade-insecure-requests;
    report-uri {CSP_REPORT_URI};
"""

# Configure Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'  # Or 'redis', 'mongodb', etc.
app.config['SESSION_PERMANENT'] = False  # Session expires when browser closes
app.config['SESSION_USE_SIGNER'] = True  # Securely sign the session cookie
app.config['SESSION_KEY_PREFIX'] = 'session:'  # Prefix for session keys
Session(app)


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = CSP
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


def is_valid_content_type(content_type):
    """
    Validates the content type against an allowlist.
    """
    # Strict allowlist for content types
    allowed_content_types = ["application/json", "text/xml", "text/plain", "application/pdf", "image/jpeg", "image/png", "text/html"]
    return content_type in allowed_content_types


@app.route('/')
@limiter.limit("10/minute")  # Example rate limit for the main route
def route():
    """
    Get the content_type parameter from the request,
    create a response with the content_type and send it as a response.
    """
    content_type = request.args.get('content_type')
    user_input = request.args.get('user_input', '')  # Get user input

    if not content_type:
        logging.warning("Content-Type parameter is missing.")
        return "Content-Type parameter is missing.", 400

    if not is_valid_content_type(content_type):
        logging.warning(f"Invalid Content-Type: {content_type}")
        return "Invalid Content-Type.", 400

    # Sanitize user input before displaying it in HTML
    sanitized_input = bleach.clean(user_input)

    # Example using render_template_string to properly escape HTML
    template = """
    <h1>Content-Type set successfully</h1>
    <p>User Input: {{ user_input }}</p>
    """
    response_html = render_template_string(template, user_input=sanitized_input)

    response = Response(response_html, mimetype=content_type)

    # Double-submitted cookie defense against CSRF
    csrf_token = secrets.token_hex(16)
    response.set_cookie('csrf_token', csrf_token, httponly=False, secure=True, samesite='Lax') # Secure=True requires HTTPS
    session['csrf_token'] = csrf_token  # Store CSRF token in session
    response.headers['X-CSRF-Token'] = csrf_token

    return response

@app.route('/your-endpoint', methods=['POST'])  # Example endpoint requiring CSRF protection
@limiter.limit("5/minute")  # Example rate limit for this endpoint
def your_endpoint():
    """
    Example endpoint that requires CSRF protection.
    """
    csrf_token_cookie = request.cookies.get('csrf_token')
    csrf_token_header = request.headers.get('X-CSRF-Token')
    csrf_token_session = session.get('csrf_token')

    if not csrf_token_cookie or not csrf_token_header or not csrf_token_session or not secrets.compare_digest(csrf_token_cookie, csrf_token_header) or not secrets.compare_digest(csrf_token_cookie, csrf_token_session):
        logging.warning("CSRF token validation failed.")
        return "CSRF token validation failed.", 400

    # Process the request
    logging.info("Request processed successfully.")
    return "Request processed successfully.", 200

@app.route(CSP_REPORT_URI, methods=['POST'])
def csp_report():
    """Endpoint to receive CSP violation reports."""
    report_data = request.get_json()
    logging.warning(f"CSP Violation Report: {report_data}")
    return Response(status=204)  # Acknowledge receipt of the report

@app.errorhandler(404)
def not_found(error):
    """Handles 404 errors."""
    logging.warning(f"404 Error: {request.path}")
    return "Not Found", 404

@app.errorhandler(500)
def internal_server_error(error):
    """Handles 500 errors."""
    logging.exception("Internal Server Error")  # Log the full exception
    return "Internal Server Error", 500

@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = json.dumps({
        "code": e.code,
        "name": e.name,
        "description": e.description,
    })
    response.content_type = "application/json"
    return response

if __name__ == '__main__':
    # Never run with debug=True in production!
    # Use a production WSGI server like gunicorn or uWSGI
    # Example: gunicorn --bind 0.0.0.0:8000 your_app:app
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8000)))

