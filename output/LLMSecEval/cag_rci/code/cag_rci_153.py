app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configure session cookie attributes
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SECURE'] = True  # Only transmit over HTTPS (set to True in production)
app.config['SESSION_PERMANENT'] = True  # Make sessions permanent

