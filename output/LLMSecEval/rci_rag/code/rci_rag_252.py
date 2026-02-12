from flask_talisman import Talisman

        csp = {
            'default-src': '\'self\'',
            'script-src': ['\'self\'', 'https://cdn.jsdelivr.net'],  # Example: Allow scripts from a CDN
            'style-src': ['\'self\'', 'https://cdn.jsdelivr.net'],   # Example: Allow styles from a CDN
            'img-src': '\'self\' data:',
            'font-src': '\'self\' https://fonts.gstatic.com',
        }

        talisman = Talisman(
            app,
            content_security_policy=csp,
            force_https=True,  # Enforce HTTPS
            session_cookie_secure=True, # Mark session cookie as secure
            session_cookie_httponly=True, # Mark session cookie as HttpOnly
        )

