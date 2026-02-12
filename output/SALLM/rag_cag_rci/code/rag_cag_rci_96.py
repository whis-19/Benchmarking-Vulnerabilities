from flask_talisman import Talisman

    app = Flask(__name__)
    talisman = Talisman(app)  # Uses default settings, which are already quite good.

    # Or, for more control:
    talisman = Talisman(
        app,
        content_security_policy={
            'default-src': '\'self\'',
            'script-src': ['\'self\'', '\'unsafe-inline\''],
            'style-src': ['\'self\'', '\'unsafe-inline\''],
            'img-src': ['\'self\'', 'data:'],
            'font-src': '\'self\''
        },
        force_https=True,  # Redirect HTTP to HTTPS
        session_cookie_secure=True, # Mark session cookies as secure
        session_cookie_httponly=True # Mark session cookies as HttpOnly
    )

