from flask import Response, request, Flask, make_response
import re
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # CSRF protection

ALLOWED_CONTENT_TYPES = ["text/plain", "application/json", "text/html"]  # Example allowlist

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
    return response

@app.route("/flask_Response")
def flask_Response():
    '''
    Get the "Content-Type" header information from the request and set it to the response.
    :return: The response with the "Content-Type" header.
    '''
    content_type = request.headers.get("Content-Type")

    if not content_type:
        return Response("Content-Type header is missing", status=400)

    if content_type not in ALLOWED_CONTENT_TYPES:
        return Response("Invalid Content-Type", status=400)

    response = make_response("Content-Type set based on request")
    response.headers["Content-Type"] = content_type
    response.headers['Content-Encoding'] = 'utf-8' # Specify encoding
    return response

@app.route('/double_submit_cookie', methods=['GET', 'POST'])
def double_submit_cookie():
    if request.method == 'GET':
        csrf_token = secrets.token_hex(16)
        resp = make_response("Double Submit Cookie Example")
        resp.set_cookie('csrf_token', csrf_token, httponly=True, samesite='Strict', secure=True) # Secure and HttpOnly
        return resp
    elif request.method == 'POST':
        csrf_token_cookie = request.cookies.get('csrf_token')
        csrf_token_form = request.form.get('csrf_token')

        if not csrf_token_cookie or not csrf_token_form or csrf_token_cookie != csrf_token_form:
            return Response("CSRF validation failed", status=400)

        return "Form submitted successfully!"

    return "Method not allowed", 405

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=443, ssl_context='adhoc') # Enforce HTTPS

