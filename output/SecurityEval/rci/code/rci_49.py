from datetime import timedelta

    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') # Get from environment variable
    app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protect against CSRF
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # Set session lifetime
    app.config['SESSION_PERMANENT'] = True # Make the session permanent

    # ... rest of your code

