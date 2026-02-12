from flask import Flask, redirect, request, render_template_string
from urllib.parse import urlparse
import secrets  # For generating nonces

app = Flask(__name__)

app.config['ALLOWED_DOMAINS'] = [
    'example.com',
    'www.example.com',
    'subdomain.example.com',
    'another-domain.net'
]

def is_allowed_domain(url, allowed_domains):
    """
    Checks if the domain of the given URL is in the list of allowed domains.
    Handles IDNs, case sensitivity, and trailing dots.
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.split(':')[0].lower()  # Normalize
        domain = domain.rstrip('.') # Remove trailing dot
        # Consider using a URL validation library here for more robust checks

        # Handle IDNs (example, requires idna library: pip install idna)
        # try:
        #     domain = domain.encode('idna').decode('ascii')
        # except UnicodeError:
        #     return False # Invalid IDN

        return domain in allowed_domains
    except Exception:
        return False

@app.route('/redirect')
def redirect_invalid_url():
    url = request.args.get('url')
    if not url:
        return "Missing URL parameter", 400

    allowed_domains = app.config['ALLOWED_DOMAINS']
    if is_allowed_domain(url, allowed_domains):
        # Generate a nonce for CSRF protection
        nonce = secrets.token_urlsafe(16)
        # Store the nonce in the session (or a similar mechanism)
        # session['redirect_nonce'] = nonce  # Requires Flask sessions

        # Display a warning page before redirecting
        return render_template_string("""
            <h1>Redirect Confirmation</h1>
            <p>You are about to be redirected to: <strong>{{ url | e }}</strong></p>  <!-- Escape the URL! -->
            <p>Do you want to continue?</p>
            <a href="{{ url }}" rel="noopener noreferrer">Yes, continue</a> | <a href="/">No, go back</a>
        """, url=url)
    else:
        app.logger.warning(f"Redirect blocked to invalid URL: {url}")
        return "Invalid URL", 400  # Use a proper HTTP error code

if __name__ == '__main__':
    app.run(debug=True)

