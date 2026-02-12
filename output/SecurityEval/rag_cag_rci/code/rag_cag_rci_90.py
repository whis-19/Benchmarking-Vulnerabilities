from flask import request, redirect, Flask
from urllib.parse import urlparse
import os

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Guideline 10

ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Guideline 2

@app.route('/flask_redirect')
def flask_redirect():
    """
    Get the url from the request and redirect to it, but only after thorough validation.
    """
    target = request.args.get('url')

    if not target:
        return "Error: No URL provided", 400

    try:
        parsed_url = urlparse(target)  # Guideline 6
    except:
        return "Error: Invalid URL", 400

    if not parsed_url.netloc:
        return "Error: Invalid URL - No network location", 400

    if parsed_url.scheme not in ['http', 'https']:
        return "Error: Invalid URL - Only HTTP/HTTPS allowed", 400

    # Check against allowlist (Guideline 2 & 8)
    if parsed_url.netloc not in ALLOWED_DOMAINS:
        return "Error: Disallowed domain", 403

    # Further sanitization (Guideline 1) - prevent XSS and other injection attacks
    sanitized_target = target.replace("<", "&lt;").replace(">", "&gt;")  # Basic XSS protection (Guideline 14)

    # Validate SSL/TLS certificates (Guideline 4) -  This is typically handled by the web server (e.g., nginx, apache)
    # and the requests library if you were making outbound requests.  Flask itself doesn't directly handle this for redirects.
    # However, ensure your web server is configured correctly for HTTPS and certificate validation.

    # Use HTTPS (Guideline 3) - Enforce HTTPS for the entire application.  This is usually done at the web server level.
    # Example (in a WSGI server config or similar):
    # if request.url.startswith('http://'):
    #     url = request.url.replace('http://', 'https://', 1)
    #     code = 301
    #     return redirect(url, code=code)

    # CSRF protection (Guideline 13) - Flask-WTF provides CSRF protection.  If you're using forms, integrate it.
    # Example:
    # from flask_wtf.csrf import CSRFProtect
    # csrf = CSRFProtect(app)

    # Content Security Policy (CSP) -  Helps prevent XSS (Guideline 14)
    # This is usually configured in the web server or as a middleware.
    # Example:
    # response = make_response(render_template('index.html'))
    # response.headers['Content-Security-Policy'] = "default-src 'self'"
    # return response

    return redirect(sanitized_target, code=302)  # Use 302 for temporary redirect

if __name__ == '__main__':
    #  Don't use debug mode in production!
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))

