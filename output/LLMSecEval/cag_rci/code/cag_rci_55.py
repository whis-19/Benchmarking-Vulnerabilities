app = Flask(__name__)

# Configure Flask-Session
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_USE_SIGNER"] = True  # Sign the session cookie to prevent tampering
app.config["SESSION_KEY_PREFIX"] = "my_app_session:"
app.config["SESSION_REDIS"] = redis.Redis(host='localhost', port=6379, db=0)
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = 'Lax'
app.config["PERMANENT_SESSION_LIFETIME"] = 3600

# IMPORTANT: Set a strong, randomly generated SECRET_KEY for your Flask application!
# This is used to sign the session cookie and protect against tampering.
app.config["SECRET_KEY"] = os.urandom(24)  # Example: Generate a random key

Session(app)

