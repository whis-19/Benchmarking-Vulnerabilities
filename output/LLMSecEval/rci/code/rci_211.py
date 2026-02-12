from flask_talisman import Talisman

     talisman = Talisman(app,
                         content_security_policy={
                             'default-src': '\'self\'',
                             'script-src': ['\'self\'', 'https://cdn.jsdelivr.net'],  # Example: Allow scripts from a CDN
                             'style-src': ['\'self\'', 'https://cdn.jsdelivr.net'],   # Example: Allow styles from a CDN
                             'img-src': ['\'self\'', 'data:']
                         },
                         force_https=True,  # Enforce HTTPS
                         session_cookie_secure=True, # Ensure session cookies are secure
                         session_cookie_http_only=True, # Prevent client-side access to session cookies
                         session_cookie_samesite='Strict' # Protect against CSRF
                         )

