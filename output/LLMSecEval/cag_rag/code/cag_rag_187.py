from urllib.parse import urlparse
from flask import Flask, redirect, abort, request, make_response

app = Flask(__name__)

ALLOWED_DOMAINS = ["example.com"]  # Use an allowlist
ALLOWED_SCHEMES = ["https"] # Only allow https

@app.route('/redirect')
def redirect_url():
    """
    Redirects to a URL if the domain is in the allowlist.
    Returns a 404 error if the domain is not allowed.
    """
    url = request.args.get('url')

    if not url:
        return "URL parameter is missing", 400

    try:
        parsed_url = urlparse(url)
    except Exception:
        return "Invalid URL", 400

    # Validate scheme
    if parsed_url.scheme not in ALLOWED_SCHEMES:
        return "Invalid URL scheme. Only HTTPS is allowed.", 400

    # Validate netloc (domain)
    if parsed_url.netloc in ALLOWED_DOMAINS:
        response = make_response(redirect(url, code=302))
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        response.set_cookie('session_cookie', 'session_value', httponly=True)
        return response
    else:
        abort(404)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8080)

