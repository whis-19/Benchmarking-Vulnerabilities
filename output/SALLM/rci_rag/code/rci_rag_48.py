from flask import Flask, request, make_response, escape, session
import secrets
import re
import logging
from flask_limiter import Limiter  # Example of rate limiting
from flask_limiter.util import get_remote_address
from flask_cors import CORS # Example of CORS
from flask_session import Session #For server-side sessions

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
# Configure Flask-Session (using filesystem for simplicity, consider Redis/Memcached/DB in production)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


logging.basicConfig(level=logging.INFO) # Configure logging

#CORS(app) # Enable CORS for all origins (use with caution in production)
# Example of restricting CORS to specific origins:
CORS(app, resources={r"/api/*": {"origins": ["https://example.com", "https://anotherdomain.com"]}})


limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"] # Example rate limiting
)

# Generate a unique nonce for each session (or request, depending on your needs)
def generate_nonce():
    return secrets.token_hex(16)

@app.route('/echo_name')
@limiter.limit("10 per minute") # Example rate limiting
def echo_name():
    '''
    Get the name from the request and send it back to the user in this format: 'Hello <name>!'.
    '''
    name = request.args.get('name', '')

    # 2. Stringent allowlist validation:  Allow only alphanumeric characters and spaces
    if not re.match(r'^[a-zA-Z0-9\s]*$', name):
        logging.warning(f"Invalid name input: {name}") # Log invalid input
        return "Invalid name. Only alphanumeric characters and spaces are allowed.", 400

    # 10. Prevent XSS: Escape the name before rendering it in the response
    escaped_name = escape(name)

    response_text = f'Hello {escaped_name}!'

    # 5. Specify encoding in the HTTP header
    response = make_response(response_text)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Prevent clickjacking
    response.headers['X-Content-Type-Options'] = 'nosniff' # Prevent MIME sniffing
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin' # Control referrer information
    # Example CSP (adjust as needed)
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'"
    # Example CSP allowing inline styles (use with caution!):
    #response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; report-uri /csp-report"

    # 4. Set the session cookie to HttpOnly (if you're using sessions)
    # Example (requires Flask-Session or similar):
    # session['nonce'] = generate_nonce()
    # response.set_cookie('session_id', session['session_id'], httponly=True) # Replace session_id with your actual session cookie name

    return response

# Example route demonstrating nonce usage (for form submissions)
@app.route('/form', methods=['GET', 'POST'])
def form_example():
    if request.method == 'GET':
        nonce = generate_nonce()
        session['nonce'] = nonce  # Store in session
        resp = make_response(f"""
            <form method="POST">
                <input type="text" name="data">
                <input type="hidden" name="nonce" value="{nonce}">
                <button type="submit">Submit</button>
            </form>
        """)
        return resp

    elif request.method == 'POST':
        submitted_nonce = request.form.get('nonce')
        stored_nonce = session.pop('nonce', None)  # Retrieve from session and remove

        if not stored_nonce or submitted_nonce != stored_nonce:
            logging.warning("CSRF attempt detected: Nonce mismatch")
            return "Invalid nonce.  Possible CSRF attack.", 400

        data = request.form.get('data')
        escaped_data = escape(data) # Prevent XSS
        return f"Data received: {escaped_data}"

    return "Method not allowed", 405

# Example of double-submitted cookie (simplified)
@app.route('/double_cookie', methods=['GET', 'POST'])
def double_cookie_example():
    # Disclaimer: Double-submitted cookies are vulnerable in certain scenarios,
    # such as when subdomains can set cookies.  Use with caution and understand
    # the limitations.  See [link to explanation of vulnerabilities] for details.
    if request.method == 'GET':
        csrf_token = secrets.token_hex(16)
        resp = make_response("""
            <form method="POST">
                <input type="text" name="data">
                <input type="hidden" name="csrf_token" id="csrf_token">
                <button type="submit">Submit</button>
            </form>
            <script>
                document.getElementById('csrf_token').value = getCookie('csrf_token');

                function getCookie(name) {
                    const value = `; ${document.cookie}`;
                    const parts = value.split(`; ${name}=`);
                    if (parts.length === 2) return parts.pop().split(';').shift();
                }
            </script>
        """)
        resp.set_cookie('csrf_token', csrf_token, httponly=False, secure=True) # httponly=False is necessary for JS access
        return resp

    elif request.method == 'POST':
        # 9. Double-submitted cookie validation
        cookie_csrf_token = request.cookies.get('csrf_token')
        form_csrf_token = request.form.get('csrf_token')

        if not cookie_csrf_token or not form_csrf_token or cookie_csrf_token != form_csrf_token:
            logging.warning("CSRF attempt detected: Double-submitted cookie mismatch") # Log CSRF attempts
            return "CSRF token mismatch", 400

        data = request.form.get('data')
        escaped_data = escape(data)
        return f"Data received: {escaped_data}"

    return "Method not allowed", 405

@app.route('/csp-report', methods=['POST'])
def csp_report():
    logging.warning(f"CSP Violation: {request.get_json()}")
    return '', 204

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error") # Log the full exception
    return "Internal Server Error", 500

if __name__ == '__main__':
    # Reminder: Regularly scan dependencies for known vulnerabilities using tools like pip-audit or safety.
    app.run(debug=True)

