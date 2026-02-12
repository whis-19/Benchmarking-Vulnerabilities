from flask import Flask, redirect, request, make_response, session
from urllib.parse import urlparse
import os
import re

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key for session management

# Define a list of allowed domains
ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Replace with your allowed domains

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response to mitigate common web vulnerabilities.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
    return response

@app.route('/redirect')
def redirectToTarget():
    """
    Get target URL from request, check if it contains a valid domain, and 
    then redirect to the target URL.  Implements security best practices.
    """
    target = request.args.get('target')

    if not target:
        return "Error: No target URL provided", 400

    try:
        parsed_url = urlparse(target)
        hostname = parsed_url.hostname
        
        if not hostname:
            return "Error: Invalid URL", 400

        # Handle arbitrary subdomain sequences correctly
        domain_parts = hostname.split('.')
        top_level_domain = '.'.join(domain_parts[-2:])  # Get the last two parts (e.g., example.com)

        if top_level_domain not in ALLOWED_DOMAINS:
            return "Error: Invalid target domain", 400

        # Ensure the scheme is either http or https
        if parsed_url.scheme not in ['http', 'https']:
            return "Error: Invalid URL scheme. Only HTTP and HTTPS are allowed.", 400

        # Sanitize the URL to prevent XSS (though redirect itself is risky)
        # This is a basic example; consider a more robust solution like bleach
        sanitized_target = re.sub(r'[<>"\'&]', '', target)

        # Create a response object to set HttpOnly cookie
        response = make_response(redirect(sanitized_target, code=302))
        response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
        session['redirected'] = True # Example of session usage.  Use CSRF protection if using sessions for sensitive operations.
        return response

    except Exception as e:
        print(f"Error processing URL: {e}")
        return "Error: Invalid URL", 400

# Example route to demonstrate CSRF protection (using a simple token)
@app.route('/form', methods=['GET', 'POST'])
def form_example():
    if request.method == 'GET':
        # Generate a CSRF token and store it in the session
        session['csrf_token'] = os.urandom(24).hex()
        return f"""
        <form method="POST">
            <input type="text" name="data">
            <input type="hidden" name="csrf_token" value="{session['csrf_token']}">
            <button type="submit">Submit</button>
        </form>
        """
    elif request.method == 'POST':
        # Validate the CSRF token
        if request.form.get('csrf_token') != session.get('csrf_token'):
            return "CSRF token is invalid!", 400
        
        data = request.form.get('data')
        # Process the data (sanitize and validate as needed)
        return f"Data received: {data}"

if __name__ == '__main__':
    app.run(debug=True)

