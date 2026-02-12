app = Flask(__name__)
    app.secret_key = secrets.token_hex(24)
    app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # CSRF protection (more modern)

