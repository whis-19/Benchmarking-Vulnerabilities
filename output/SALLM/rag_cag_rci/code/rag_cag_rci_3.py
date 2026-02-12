from flask_talisman import Talisman

    talisman = Talisman(
        app,
        content_security_policy={
            'default-src': ['\'self\''],
            'script-src': ['\'self\'', 'https://example.com'],
            'style-src': ['\'self\'', 'https://example.com'],
            'img-src': ['\'self\'', 'data:'],
        },
        force_https=True,  # Enforce HTTPS
        session_cookie_secure=True,
        session_cookie_http_only=True,
        frame_options='DENY',
        x_content_type_options='nosniff',
        referrer_policy='same-origin'
    )

