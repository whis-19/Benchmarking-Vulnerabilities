import secrets
from flask import Flask, session, request, after_request, render_template_string

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong, random key!

# Secure Session Configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Only enable in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Or 'Strict' depending on your needs

def generate_nonce():
    return secrets.token_hex(16)

@app.before_request
def before_request():
    if 'csp_nonce' not in session:
        session['csp_nonce'] = generate_nonce()

@app.after_request
def add_csp_header(response):
    nonce = session.get('csp_nonce')
    if nonce:  # Only add CSP if nonce exists
        csp = {
            'default-src': "'self'",
            'script-src': f"'self' 'nonce-{nonce}'",
            'style-src': f"'self' 'nonce-{nonce}'",
            'img-src': "'self' data:",
            'font-src': "'self'",
            'object-src': "'none'",
            'base-uri': "'none'",
            'form-action': "'self'",
            'frame-ancestors': "'none'",
            'report-uri': '/csp_report'
        }
        csp_string = "; ".join(f"{k} {v}" for k, v in csp.items())
        response.headers['Content-Security-Policy'] = csp_string
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.route('/csp_report', methods=['POST'])
def csp_report():
    # TODO: Implement rate limiting, authentication, and data validation here!
    if request.content_type != 'application/json':
        return 'Invalid Content-Type', 400

    report_data = request.get_json()

    # Example Data Validation (Expand this!)
    try:
        blocked_uri = report_data.get('blocked-uri', '')
        if blocked_uri and not blocked_uri.startswith(('https://yourdomain.com', 'http://yourdomain.com')):
            print(f"Suspicious blocked-uri: {blocked_uri}") # Log securely
            # Consider rejecting the report or taking further action

        # Add more validation for other fields like 'violated-directive', etc.
    except (AttributeError, TypeError) as e:
        print(f"Error processing CSP report: {e}") # Log securely
        return 'Invalid CSP Report Format', 400

    print("CSP Report:", report_data)  # Log securely!
    return '', 204

@app.route('/')
def index():
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CSP Example</title>
    </head>
    <body>
        <h1>Hello, World!</h1>
        <p>Welcome, {{ user.name | e }}!</p>
        <script nonce="{{ session['csp_nonce'] }}">
            console.log("Inline script with nonce!");
        </script>
        <style nonce="{{ session['csp_nonce'] }}">
            body { background-color: lightblue; }
        </style>
    </body>
    </html>
    """
    user = {'name': '<b>John Doe</b>'} # Example with potentially unsafe HTML
    return render_template_string(template, user=user)

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc') # Use 'adhoc' for testing only.  Use proper certificates in production.

