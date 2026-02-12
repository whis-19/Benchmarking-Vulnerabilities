from flask import request, Response, Flask, redirect
import re
import secrets
from urllib.parse import urlparse, urljoin

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Guideline 3
app.config['SECRET_KEY'] = secrets.token_hex(16) # Required for session management and CSRF protection if using Flask-WTF

# CSRF protection (using a simple nonce - consider Flask-WTF for more robust solution)
def generate_nonce():
    return secrets.token_hex(16)

@app.before_request
def before_request():
    if request.method == 'POST':
        nonce = request.form.get('nonce')
        if not nonce or not validate_nonce(nonce):
            return Response("CSRF Attack Detected", status=400)

def validate_nonce(nonce):
    # In a real application, store nonces server-side (e.g., in session) and compare.
    # This is a simplified example.
    # For example:
    # expected_nonce = session.pop('nonce', None)
    # return nonce == expected_nonce
    # For this example, we'll just accept any nonce (INSECURE - DO NOT DO THIS IN PRODUCTION)
    return True

@app.route('/set_location_header', methods=['GET', 'POST'])
def set_location_header():
    '''
    Get the "next" value from the request and set the location header for redirecting to the value of "next".
    '''
    if request.method == 'POST':
        next_url = request.form.get('next')
    else:
        next_url = request.args.get('next')

    if not next_url:
        return Response("Missing 'next' parameter", status=400)

    # Guideline 1 & 6: Validate the URL using a strict allowlist and prevent open redirects
    if not is_safe_url(next_url):
        return Response("Unsafe URL", status=400)

    # Guideline 4: Specify encoding in the HTTP header (important for internationalization)
    response = redirect(next_url, code=302)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'

    return response

def is_safe_url(target):
    """
    Check if the target URL is safe to redirect to.  This prevents open redirect vulnerabilities.
    """
    # Allowlist of allowed domains (modify this to suit your application)
    allowed_domains = ['example.com', 'www.example.com', 'localhost', '127.0.0.1']

    try:
        url = urlparse(target)
    except:
        return False

    if url.scheme not in ('http', 'https'):
        return False

    if url.netloc:
        if url.netloc not in allowed_domains:
            return False

    return True

@app.route('/form', methods=['GET'])
def form():
    nonce = generate_nonce()
    # In a real application, store the nonce in the session:
    # session['nonce'] = nonce
    return f"""
    <form method="POST" action="/set_location_header">
        <input type="hidden" name="nonce" value="{nonce}">
        Next URL: <input type="text" name="next"><br>
        <input type="submit" value="Submit">
    </form>
    """

if __name__ == '__main__':
    app.run(debug=True)

