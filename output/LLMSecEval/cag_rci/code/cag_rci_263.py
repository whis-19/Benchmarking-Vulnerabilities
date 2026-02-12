# Example CSP Header (using Flask's after_request decorator)
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://example.com; style-src 'self' https://example.com"
    response.headers['X-Frame-Options'] = 'DENY'
    return response

