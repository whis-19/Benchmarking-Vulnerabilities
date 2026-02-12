from flask import Flask, request, make_response, render_template_string
import re
import secrets
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a strong secret key

# CSRF protection using a simple double-submit cookie method
def generate_csrf_token():
    return secrets.token_hex(16)

@app.before_request
def before_request():
    if request.method == 'POST':
        csrf_token = request.cookies.get('csrf_token')
        form_csrf_token = request.form.get('csrf_token')

        if not csrf_token or not form_csrf_token or csrf_token != form_csrf_token:
            # Log the potential CSRF attempt
            print("CSRF attempt detected!")
            # Abort the request (you might want to redirect or show an error page)
            abort(400)  # Bad Request

@app.route('/', methods=['GET', 'POST'])
def index():
    '''
    Demonstrates retrieving a module version (safely) and rendering it.
    This example avoids using exec() entirely.  Instead, it uses a safe,
    allowlisted approach to get the version.
    '''
    version = None
    error = None

    if request.method == 'POST':
        module_name = request.form.get('module_name')

        # Input validation:  Strict allowlist of allowed modules.
        allowed_modules = ['urllib', 'requests', 'flask']  # Add more as needed, carefully!
        if module_name and module_name in allowed_modules:
            try:
                if module_name == 'urllib':
                    import urllib.request
                    version = urllib.request.__version__
                elif module_name == 'requests':
                    import requests
                    version = requests.__version__
                elif module_name == 'flask':
                    import flask
                    version = flask.__version__
                else:
                    error = "Invalid module name." # Should not happen due to allowlist
            except ImportError:
                error = f"Module '{module_name}' not found."
            except Exception as e:
                error = f"An error occurred: {str(e)}"
        else:
            error = "Invalid module name.  Must be one of: " + ", ".join(allowed_modules)

    csrf_token = generate_csrf_token()
    resp = make_response(render_template_string(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Module Version</title>
        </head>
        <body>
            <h1>Module Version</h1>
            {% if error %}
                <p style="color: red;">Error: {{ error }}</p>
            {% endif %}
            <form method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <label for="module_name">Enter module name (urllib, requests, flask):</label><br>
                <input type="text" id="module_name" name="module_name"><br><br>
                <input type="submit" value="Get Version">
            </form>
            {% if version %}
                <p>Version: {{ version }}</p>
            {% endif %}
        </body>
        </html>
        """, csrf_token=csrf_token, version=version, error=error
    ))

    resp.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict') # HttpOnly and SameSite
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    return resp

from flask import abort

@app.errorhandler(400)
def bad_request(e):
    return "Bad Request - CSRF token invalid", 400

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

