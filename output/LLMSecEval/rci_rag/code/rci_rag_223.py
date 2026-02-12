import os
import secrets
from flask import Flask, request, render_template, make_response, abort
import yaml
from markupsafe import escape
from cerberus import Validator
from flask_limiter import Limiter
from flask_limiter.util import get_ipaddr

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['TRUSTED_PROXIES'] = ['127.0.0.1']

limiter = Limiter(
    get_ipaddr,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

def generate_csrf_token():
    return secrets.token_hex(16)

def set_csrf_cookie(response, csrf_token):
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')
    return csrf_token

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def index():
    if request.method == 'GET':
        csrf_token = generate_csrf_token()
        response = make_response(render_template('index.html', csrf_token=csrf_token))
        set_csrf_cookie(response, csrf_token)
        return response
    elif request.method == 'POST':
        referer = request.headers.get('Referer')
        if not referer or not referer.startswith(request.url_root):
            abort(400, "Invalid Referer header")

        form_csrf_token = request.form.get('csrf_token')
        cookie_csrf_token = request.cookies.get('csrf_token')

        if not form_csrf_token or not cookie_csrf_token or form_csrf_token != cookie_csrf_token:
            abort(400, "CSRF token mismatch")

        payload = request.form.get('payload')

        if not payload:
            return "Error: Payload parameter is missing", 400

        try:
            data = yaml.safe_load(payload)
        except yaml.YAMLError as e:
            return f"Error: Invalid YAML format - {escape(str(e))}", 400

        schema = {
            'type': {'type': 'string', 'required': True, 'allowed': ['Read', 'Update']},
            'data': {
                'type': 'dict',
                'required': False,
                'schema': {
                    'key1': {'type': 'string', 'required': True},
                    'key2': {'type': 'integer', 'required': False, 'min': 0, 'max': 100},
                }
            }
        }

        v = Validator(schema)
        if not v.validate(data):
            return f"Error: Invalid YAML data - {escape(str(v.errors))}", 400

        if isinstance(data, dict) and data.get('type') == 'Create':
            return "Error: 'Create' type is not allowed", 400

        return f"Payload processed successfully: {escape(str(data))}"
    return "Method not allowed", 405

@app.errorhandler(400)
def bad_request(error):
    return f"Bad Request: {escape(str(error))}", 400

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;"
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

