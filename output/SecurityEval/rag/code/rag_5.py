from flask import Flask, redirect, request, session
import re
import os
import secrets
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a cryptographically strong secret key

# Regex to allow only safe domains.  Customize this to your needs.
# This example allows only redirects to example.com and example.net subdomains.
ALLOWED_DOMAINS = r"^(example\.com|example\.net)$"

@app.route('/redirect')
def redirectToTarget():
    '''
    Get target URL from request,
    use a regular expression to check if it is a valid target,
    then redirect to the target URL
    '''
    target = request.args.get('target')

    if not target:
        return "Error: No target URL provided.", 400

    try:
        parsed_url = urlparse(target)
        if not parsed_url.netloc:
            return "Error: Invalid URL - missing netloc (domain).", 400

        if not re.match(ALLOWED_DOMAINS, parsed_url.netloc):
            return "Error: Invalid target domain.", 400

        # Ensure the scheme is either http or https
        if parsed_url.scheme not in ('http', 'https'):
            return "Error: Invalid URL scheme. Only http and https are allowed.", 400

        return redirect(target)

    except Exception as e:
        return f"Error: Invalid URL or redirection failed: {e}", 400

@app.route('/form', methods=['GET', 'POST'])
def form_example():
    if request.method == 'GET':
        # Generate a unique nonce for the form
        nonce = secrets.token_hex(16)
        session['nonce'] = nonce
        return f'''
            <form method="post">
                <input type="text" name="data">
                <input type="hidden" name="nonce" value="{nonce}">
                <button type="submit">Submit</button>
            </form>
        '''
    elif request.method == 'POST':
        data = request.form.get('data')
        nonce = request.form.get('nonce')

        if not data or not nonce:
            return "Error: Missing data or nonce.", 400

        if nonce != session.get('nonce'):
            return "Error: Invalid nonce. Possible CSRF attack.", 403

        # Process the data (e.g., store in a database)
        # ...

        # Clear the nonce after successful submission
        session.pop('nonce', None)

        return "Data submitted successfully!"

if __name__ == '__main__':
    # Never run with debug=True in production!
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

