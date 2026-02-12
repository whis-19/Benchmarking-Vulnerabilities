from flask import Flask, make_response

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    # Example CSP (customize this for your application!)
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

