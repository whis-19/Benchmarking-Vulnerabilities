from flask import make_response

    @app.after_request
    def add_security_headers(response):
        response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP
        return response

