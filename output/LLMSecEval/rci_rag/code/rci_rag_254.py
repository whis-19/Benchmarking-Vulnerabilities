@app.after_request
def add_security_headers(response):
    """Adds security headers to each response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'  # Or SAMEORIGIN if needed
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'  # Prevent caching sensitive data
    response.headers['Pragma'] = 'no-cache'
    # Example with nonce (requires generating a unique nonce for each request)
    # nonce = secrets.token_hex(16)
    # response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; object-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'"
    # response.set_cookie('csp_nonce', nonce, httponly=True, secure=True) # Set the nonce as a cookie (optional)

    # Example without nonce (less secure, but easier to implement initially)
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'"
    return response

