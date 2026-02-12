from flask import Flask, request, redirect, url_for, send_from_directory, make_response

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

