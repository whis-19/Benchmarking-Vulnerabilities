from flask import Flask, make_response
import secrets  # Import the secrets module

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.example.com; img-src 'self' data:; style-src 'self' https://fonts.googleapis.com; report-to csp-endpoint;"  # Adjust as needed
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Report-To'] = '{"group": "csp-endpoint", "max_age": 31536000, "endpoints": [{"url": "https://your-csp-reporting-endpoint.com"}]}' # Replace with your reporting endpoint
    response.headers['Content-Security-Policy-Report-Only'] = "default-src 'self'; report-to csp-endpoint;" # Report-only CSP for testing
    return response

@app.route('/')
def index():
    response = make_response("Hello, World!")
    response.set_cookie('session_id', secrets.token_hex(16), secure=True, httponly=True)  # Use secrets.token_hex to generate a secure session ID
    return response

