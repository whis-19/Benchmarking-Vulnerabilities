import secrets
    from flask import Flask, render_template

    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_hex(16)

    @app.after_request
    def add_csp_header(response):
        nonce = secrets.token_urlsafe(16)
        response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self';"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.set_cookie('csp_nonce', nonce, httponly=True, secure=True) # Secure and HttpOnly cookie
        return response

    @app.route('/')
    def index():
        nonce = request.cookies.get('csp_nonce')
        return render_template('index.html', nonce=nonce)

