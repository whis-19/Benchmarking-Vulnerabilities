from flask import Flask, Response

    app = Flask(__name__)

    @app.after_request
    def add_security_headers(response):
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'none'; object-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';"
        return response

