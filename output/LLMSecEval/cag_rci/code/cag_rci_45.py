# Consider using Flask-Session for more robust session management: pip install Flask-Session
# from flask_session import Session

# app.config['SESSION_TYPE'] = 'redis'  # Or 'memcached', 'filesystem', etc.
# app.config['SESSION_REDIS'] = redis.Redis(host='localhost', port=6379, db=0) # Configure Redis
# app.config['SESSION_PERMANENT'] = True  # Make sessions persistent
# app.config['SESSION_USE_SIGNER'] = True  # Sign the session cookie
# app.config['SESSION_KEY_PREFIX'] = 'session:'  # Optional prefix for session keys

# Session(app) # Initialize Flask-Session

