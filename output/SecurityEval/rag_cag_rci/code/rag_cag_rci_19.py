from flask import make_response

    @app.route("/")
    def index():
        response = make_response("<h1>Hello, World!</h1>")
        response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP
        return response

