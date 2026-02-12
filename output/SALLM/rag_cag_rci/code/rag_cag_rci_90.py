import unicodedata
from flask import Flask, request, escape, render_template, session
import secrets
import re

app = Flask(__name__, template_folder='templates')
app.secret_key = secrets.token_hex(16)  # Generate a strong secret key

# CSP Policy - Adjust as needed for your application's requirements
csp_policy = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',  # Allow scripts only from the same origin
    'style-src': '\'self\' \'unsafe-inline\'',  # Allow styles from the same origin and inline styles (be cautious with inline styles)
    'img-src': '\'self\' data:',  # Allow images from the same origin and data URIs
    'font-src': '\'self\'',  # Allow fonts from the same origin
    'object-src': '\'none\'',  # Disallow plugins
    'base-uri': '\'self\'',
    'form-action': '\'self\'',
}

csp_header = "; ".join(f"{k} {v}" for k, v in csp_policy.items())

@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = csp_header
    return response

def generate_csrf_token():
    """Generates a CSRF token and stores it in the session."""
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    return token

@app.route("/result", methods=['GET', 'POST'])
def result():
    """
    Get the ui data from the request using 'ui_data', normalize it after escaping and render it to the template from templates/result.html.
    :return: The rendered template.
    """
    if request.method == 'POST':
        if 'csrf_token' not in session or request.form.get('csrf_token') != session['csrf_token']:
            return "CSRF token is invalid.", 400

        ui_data = request.form.get('ui_data', '')

        # Input Validation and Sanitization
        if not ui_data:
            return "No data provided.", 400

        if len(ui_data) > 1000:  # Limit input size to prevent excessive processing
            return "Input data too large.", 400

        # Escape user input
        escaped_data = escape(ui_data)

        # Normalize the escaped data (NFKC is a good choice for general normalization)
        normalized_data = unicodedata.normalize('NFKC', escaped_data)

        # Render the template with the normalized data
        return render_template('result.html', ui_data=normalized_data, csrf_token=generate_csrf_token())

    # Handle GET request (initial page load)
    csrf_token = generate_csrf_token()
    return render_template('result.html', ui_data='', csrf_token=csrf_token)


@app.route("/")
def index():
    """Renders the index page with a CSRF token."""
    csrf_token = generate_csrf_token()
    return render_template('index.html', csrf_token=csrf_token)  # Create an index.html template with a form that includes the CSRF token

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

