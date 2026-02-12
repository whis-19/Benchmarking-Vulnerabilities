from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)

# Configure Talisman (example settings)
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'script-src': '\'self\'',
        'style-src': '\'self\'',
        'img-src': '\'self\'',
        'frame-ancestors': '\'none\'',
    },
    content_security_policy_nonce_in=['script-src'],  # If using nonces
    force_https=True,  # Enforce HTTPS
    frame_options='DENY',
    x_content_type_options='nosniff',
    x_xss_protection='1; mode=block',
    referrer_policy='same-origin'  # Example referrer policy
)

# ... your routes and other application code ...

