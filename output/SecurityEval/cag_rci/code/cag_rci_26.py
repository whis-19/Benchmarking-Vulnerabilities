import secrets
from flask import Flask, render_template_string, request, make_response, send_from_directory
import logging
from werkzeug.security import safe_join  # For path traversal protection

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # For session management and CSRF protection - use a strong, random key!

logging.basicConfig(filename='csp_violations.log', level=logging.WARNING)

@app.route('/')
def index():
    nonce = secrets.token_urlsafe(16)
    csp = (
        "default-src 'self';"
        " script-src 'self' 'nonce-{nonce}' https://cdnjs.cloudflare.com;"
        " style-src 'self';"  # Removed 'unsafe-inline'
        " img-src 'self' data:;"
        " font-src 'self';"
        " connect-src 'self';"
        " frame-ancestors 'self';"
        " report-uri /csp-report;"
    )
    return render_template_string(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <title>CSP Example</title>
            <meta http-equiv="Content-Security-Policy" content="{{ csp }}">
            <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
        </head>
        <body>
            <h1>CSP Example</h1>
            <script nonce="{{ nonce }}" src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
            <script nonce="{{ nonce }}">
                $(document).ready(function() {
                    alert('Hello from jQuery!');
                });
            </script>
            <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w+gYQAUYmBiAAAB0gA8E2+wtAAAAABJRU5ErkJggg==" alt="Inline Image">
        </body>
        </html>
        """,
        csp=csp,
        nonce=nonce
    )

@app.route('/csp-report', methods=['POST'])
def csp_report():
    report = request.get_json()
    logging.warning(f"CSP Violation: {report}")
    # Analyze the CSP violation report to identify potential XSS vulnerabilities and refine the CSP.
    # CSP reporting is an iterative process.
    return '', 204

@app.route('/static/<path:filename>')
def serve_static(filename):
    # Use safe_join to prevent path traversal vulnerabilities
    safe_path = safe_join(app.root_path, 'static', filename)
    if safe_path is None:
        # Abort with a 404 error if the requested path is outside the 'static' directory.
        abort(404)
    return send_from_directory('static', filename)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Or 'DENY' if no framing is needed.  DENY is most secure, but ensure browser compatibility.
    # response.headers['X-XSS-Protection'] = '1; mode=block' # Remove this - it's obsolete and can introduce vulnerabilities.
    response.headers['Content-Security-Policy'] = response.headers.get('Content-Security-Policy', "default-src 'self'") # Use the CSP defined in the route
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload' # HSTS for 1 year
    return response

if __name__ == '__main__':
    app.run(debug=True) # NEVER run with debug=True in production!

