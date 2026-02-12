from flask import Flask
    from flask_talisman import Talisman

    app = Flask(__name__)

    talisman = Talisman(
        app,
        content_security_policy={
            'default-src': '\'self\'',
            'script-src': ['\'self\'', 'https://example.com'],
            'style-src': ['\'self\'', '\'unsafe-inline\'']  # Be careful with 'unsafe-inline'
        },
        force_https=True,  # Redirect HTTP to HTTPS
        frame_options='DENY',
        x_content_type_options='nosniff',
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,  # 1 year
        strict_transport_security_include_subdomains=True,
        referrer_policy='no-referrer'
    )

