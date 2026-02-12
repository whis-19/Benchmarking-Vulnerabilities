# --- Database Integration (Example - very basic) ---
# from flask_sqlalchemy import SQLAlchemy
# app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", 'sqlite:///:memory:') # Replace with your DB URL
# db = SQLAlchemy(app)

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(80), unique=True, nullable=False)
#     password_hash = db.Column(db.String(120), nullable=False)
#     salt = db.Column(db.String(32), nullable=False)
#     role = db.Column(db.String(20), default='user')

# with app.app_context(): # Required for db operations outside of a request context
#     db.create_all()

# --- Password Reset (High-Level Outline) ---
# 1. Generate a unique, time-limited token (e.g., using itsdangerous).
# 2. Store the token in the database, associated with the user.
# 3. Send an email to the user with a link containing the token.
# 4. When the user clicks the link, verify the token's validity and expiration.
# 5. If the token is valid, allow the user to reset their password.

# --- Key Rotation Details ---
# To rotate the encryption key:
# 1. Generate a new ENCRYPTION_KEY.
# 2. Re-encrypt all data in the database using the new key.
# 3. (Optionally) Keep the old key temporarily to decrypt any data not yet re-encrypted.
# 4. Securely delete the old key.

# --- CSP Nonces/Hashes (Example) ---
# from itsdangerous import URLSafeTimedSerializer
# app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
# def generate_nonce():
#     s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
#     return s.dumps(secrets.token_urlsafe(16))

# @app.route('/')
# @login_required()
# @limiter.limit("20/minute")
# def index():
#     """Displays the index page."""
#     username = session['username']
#     nonce = generate_nonce()
#     session['csp_nonce'] = nonce # Store in session
#     return render_template('index.html', username=username, nonce=nonce)

# In your template (index.html):
# <script src="your_script.js" nonce="{{ session['csp_nonce'] }}"></script>
# Update CSP: 'script-src': ["'self'", 'https://cdn.jsdelivr.net', "'nonce-{{ session['csp_nonce'] }}'"]

# --- Rate Limiting Customization (Example) ---
# def admin_rate_limit():
#     if session.get('username') and user_db.get(session['username'])['role'] == 'admin':
#         return "5/minute"  # More restrictive for admins
#     return "20/minute"

# limiter = Limiter(
#     get_remote_address,
#     app=app,
#     storage_uri=app.config['RATELIMIT_STORAGE_URI'],
#     strategy="fixed-window",
#     key_func=admin_rate_limit # Use the custom rate limit function
# )

# --- Environment Variable Security ---
# Use a .env file for local development (pip install python-dotenv)
# NEVER commit .env files to version control!
# In production, use a secure key management system like HashiCorp Vault, AWS KMS, or Azure Key Vault.

# --- Logging Example ---
# import logging
# logging.basicConfig(level=logging.INFO) # Configure basic logging
# app.logger.info(f"User {username} logged in successfully.")

