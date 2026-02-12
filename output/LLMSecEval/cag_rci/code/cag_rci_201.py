from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)

csp = {
    'default-src': ['\'self\''],
    'script-src': ['\'self\'', 'https://cdn.example.com'], # Allow scripts from your domain and a trusted CDN
    'style-src': ['\'self\'', 'https://fonts.googleapis.com'], # Allow styles from your domain and Google Fonts
    'img-src': ['\'self\'', 'data:'], # Allow images from your domain and data URIs
}

talisman = Talisman(app, content_security_policy=csp)

# ... your routes ...

