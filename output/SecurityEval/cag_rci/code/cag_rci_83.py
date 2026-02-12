from flask import Flask, request, make_response, render_template
import secrets
import os  # For environment variables
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Rate Limiting
limiter = Limiter(app, key_func=get_remote_address)

# Database configuration (example - replace with your actual configuration)
# DATABASE_URL = os.environ.get("DATABASE_URL")  # Get from environment variable

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'

    csp = "default-src 'self'; " \
          "script-src 'self' 'nonce-{nonce}' https://cdn.example.com; " \
          "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " \
          "img-src 'self' data: https://images.example.com; " \
          "font-src 'self' https://fonts.gstatic.com; " \
          "connect-src 'self' wss://your-websocket-server.com;" \
          "report-uri /csp-report;"

    response.headers['Content-Security-Policy'] = csp
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=()'
    return response

@app.route('/csp-report', methods=['POST'])
def csp_report():
    try:
        report_data = request.get_json()
        print("CSP Report:", report_data)
    except Exception as e:
        print(f"Error processing CSP report: {e}")
        return 'Invalid CSP Report', 400
    return '', 204

@app.route('/')
def index():
    nonce = secrets.token_urlsafe(16)
    csp = f"default-src 'self'; script-src 'self' 'nonce-{nonce}';"
    response = make_response(render_template('index.html', nonce=nonce))
    response.headers['Content-Security-Policy'] = csp
    return response

# Example route with potential database interaction (Illustrative)
# @app.route('/users/<username>')
# def get_user(username):
#     # NEVER do this directly!  SQL Injection risk!
#     # query = "SELECT * FROM users WHERE username = '" + username + "'"
#
#     # Instead, use parameterized queries:
#     # cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
#     # user = cursor.fetchone()
#     # return render_template('user.html', user=user)
#     return "User page (database interaction needs secure implementation)"

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    # Implement login logic here
    return "Login page (with rate limiting)"

if __name__ == '__main__':
    # NEVER use adhoc in production!
    # Use proper certificates.  Example using environment variables:
    # context = (os.environ.get("CERT_FILE"), os.environ.get("KEY_FILE"))
    # app.run(debug=False, ssl_context=context)

    app.run(debug=True, ssl_context='adhoc') # Only for local testing

