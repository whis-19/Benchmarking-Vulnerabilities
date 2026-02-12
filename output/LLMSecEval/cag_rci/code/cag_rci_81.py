# CSRF Decorator
def generate_csrf_token():
    """Generates a CSRF token."""
    return secrets.token_hex(16)

def validate_csrf(f):
    """Decorator to validate CSRF token."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = session.pop('_csrf_token', None)
            form_token = request.form.get('_csrf_token')

            if not token or token != form_token:
                logging.warning(f"CSRF token validation failed.  Token: {token}, Form Token: {form_token}, IP: {request.remote_addr}")
                abort(403)  # Forbidden

            # Recommendation: Invalidate the CSRF token after successful submission
            session['_csrf_token'] = None
        return f(*args, **kwargs)
    return decorated_function

# Recommendation: Double-Submit Cookie Approach (Conceptual Example)
# 1. Generate a CSRF token and store it in a cookie.
# 2. Include the same token in a hidden field in the form.
# 3. On submission, compare the cookie value with the form field value.

@app.after_request
def add_security_headers(response):
    """Adds security headers to each response."""
    response.headers['Content-Security-Policy'] = generate_csp_header(CSP_POLICY)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block' # Recommendation: Consider removing this header
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Example CSP additions:
# If using Google Analytics:
# CSP_POLICY['script-src'] = "'self' https://www.google-analytics.com https://www.googletagmanager.com"
# CSP_POLICY['connect-src'] = "'self' https://www.google-analytics.com"
# If using a CDN for fonts:
# CSP_POLICY['font-src'] = "'self' https://your-cdn.com"

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serves uploaded files securely."""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not validate_filepath(filepath):
        abort(400)  # Bad Request

    try:
        # Recommendation: Set Content-Disposition to attachment to force download
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True, download_name=filename)
    except FileNotFoundError:
        abort(404)  # Not Found

# Rate Limiting (Example - Conceptual)
# Recommendation: Use Flask-Limiter or implement a custom solution with Redis
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address
# limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
# @app.route('/upload', methods=['POST'])
# @limiter.limit("5 per minute") # Example: Limit uploads to 5 per minute
# def upload():
#     # ... your upload logic ...

@app.errorhandler(500)
def internal_server_error(e):
    """Handles 500 Internal Server Errors."""
    logging.exception("Internal Server Error") # Log the full exception
    # Recommendation: Add contextual information to the log message (e.g., user ID)
    # logging.exception(f"Internal Server Error for user {session.get('user_id', 'unknown')}")
    return render_template('error.html', error_code=500, message="An unexpected error occurred. Please try again later."), 500 # Generic message for production

# Recommendation: Enforce HTTPS at the server level (e.g., Nginx, Apache)
# This ensures that all traffic is encrypted, even if the Flask application is misconfigured.

