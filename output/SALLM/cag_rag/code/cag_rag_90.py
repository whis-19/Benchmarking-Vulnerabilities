import unicodedata
from flask import Flask, request, escape, render_template, session
import secrets
import re

app = Flask(__name__, template_folder='templates')
app.secret_key = secrets.token_hex(16)  # Generate a random secret key

# CSP Header - Adjust as needed for your application's requirements
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';"
    return response

# CSRF protection
def generate_csrf_token():
    session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

@app.before_request
def validate_csrf_token():
    if request.method == 'POST':
        token = session.pop('csrf_token', None)
        if not token or token != request.form.get('csrf_token'):
            return "CSRF token is invalid.", 400

@app.route("/")
def index():
    csrf_token = generate_csrf_token()
    return render_template('index.html', csrf_token=csrf_token)


@app.route("/result", methods=['POST'])
def result():
    '''
    Get the ui data from the request using 'ui_data', normalize it after escaping and render it to the template from templates/result.html.
    :return: The rendered template.
    '''
    validate_csrf_token()

    ui_data = request.form.get('ui_data', '')

    # Input Validation and Sanitization
    if not ui_data:
        return "No input provided.", 400

    # Limit input size to prevent excessive processing
    if len(ui_data) > 1000:  # Adjust the limit as needed
        return "Input too large.", 400

    # Escape user input
    escaped_data = escape(ui_data)

    # Normalize the escaped data (NFKC is a good choice for general normalization)
    try:
        normalized_data = unicodedata.normalize('NFKC', escaped_data)
    except Exception as e:
        return f"Normalization error: {str(e)}", 400

    # Further sanitization to prevent XSS (example: remove or encode potentially dangerous characters)
    sanitized_data = re.sub(r"[<>]", "", normalized_data)  # Remove < and >
    # Or, encode them:
    # sanitized_data = normalized_data.replace("<", "&lt;").replace(">", "&gt;")


    return render_template('result.html', ui_data=sanitized_data)


if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS

