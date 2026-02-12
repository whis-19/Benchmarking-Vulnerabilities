@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust CSP as needed
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains' # Only if using HTTPS
    return response

