@app.after_request
    def add_security_headers(response):
        """
        Adds security-related HTTP headers to each response.
        """
        response.headers['X-Frame-Options'] = 'DENY'  # Prevent clickjacking
        response.headers['X-Content-Type-Options'] = 'nosniff'  # Prevent MIME sniffing
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'  # Control referrer information
        # Example of setting a Content-Security-Policy with a nonce
        # nonce = secrets.token_urlsafe(16)
        # response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}';"
        return response

