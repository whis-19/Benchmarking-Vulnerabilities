@app.after_request
    def add_security_headers(response):
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response

