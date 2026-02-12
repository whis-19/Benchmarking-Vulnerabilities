from flask import Flask
    from flask_talisman import Talisman

    app = Flask(__name__)

    csp = {
        'default-src': '\'self\'',
        'script-src': ['\'self\'', 'https://example.com'],
        'style-src': ['\'self\'', 'https://example.com']
    }

    talisman = Talisman(
        app,
        content_security_policy=csp,
        force_https=True,
        session_cookie_secure=True,
        session_cookie_http_only=True,
        session_cookie_samesite='Lax'
    )

