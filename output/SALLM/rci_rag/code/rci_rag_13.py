from flask import Flask, request, make_response, abort
import secrets
import hmac
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Replace with a secure secret key

def generate_csrf_token():
    return secrets.token_hex(16)

def requires_csrf(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        cookie_token = request.cookies.get('csrf_token')
        form_token = request.form.get('csrf_token')

        if not (cookie_token and form_token):
            abort(400, "Missing CSRF token")

        if not hmac.compare_digest(cookie_token, form_token):
            abort(400, "CSRF token mismatch")

        return f(*args, **kwargs)
    return decorated_function

@app.route('/form', methods=['GET'])
def form():
    csrf_token = generate_csrf_token()
    resp = make_response(f"""
        <form method="post" action="/submit">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <button type="submit">Submit</button>
        </form>
    """)
    resp.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict')
    return resp

@app.route('/submit', methods=['POST'])
@requires_csrf
def submit():
    return "Form submitted successfully!"

if __name__ == '__main__':
    app.run(debug=True)

