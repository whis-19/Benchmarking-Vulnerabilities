app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Only enable in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Or 'Strict'

