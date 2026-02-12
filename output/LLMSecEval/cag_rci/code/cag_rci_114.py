from flask import Flask, render_template, request, make_response
import secrets

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    nonce = secrets.token_urlsafe(16)  # Generate a random nonce
    csp = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'; img-src 'self' data:; object-src 'none'; report-to csp-endpoint;"
    response.headers['Content-Security-Policy'] = csp
    response.headers['Report-To'] = '{"group": "csp-endpoint", "max_age": 10886400, "endpoints": [{"url": "https://your-report-uri.com/csp-report"}]}'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.nonce = nonce  # Store the nonce for use in the template
    return response

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)

