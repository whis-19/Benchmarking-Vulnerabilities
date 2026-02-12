import os
import secrets
import logging  # Import the logging module
from flask import Flask  # Import Flask
from flask import session # Import session
# from flask_wtf.csrf import CSRFProtect # Example of CSRF protection

# Configure logging (important for security auditing)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration
DATABASE_URL = os.environ.get("DATABASE_URL")
DATABASE_USER = os.environ.get("DATABASE_USER")
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")

# API key
API_KEY = os.environ.get("MY_API_KEY")

# Flask secret key
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not FLASK_SECRET_KEY:
    FLASK_SECRET_KEY = secrets.token_hex(24)
    logging.warning("FLASK_SECRET_KEY not set in environment.  Generated a random key.  This will invalidate sessions on restart unless persisted.")
    # TODO: Persist the generated key to a secure location (e.g., a file, database, or secrets manager)
    # Example (using a file - BE VERY CAREFUL WITH THIS IN PRODUCTION):
    SECRET_FILE = os.path.join(os.getcwd(), ".flask_secret") # Use os.path.join for cross-platform compatibility
    try:
        with open(SECRET_FILE, "w") as f:
            f.write(FLASK_SECRET_KEY)
    except Exception as e:
        logging.error(f"Error writing secret key to file: {e}")
    #  Then, on subsequent startups:
    #  try:
    #      with open(SECRET_FILE, "r") as f:
    #          FLASK_SECRET_KEY = f.read().strip()
    #  except FileNotFoundError:
    #      # Generate and persist as before
else:
    logging.info("FLASK_SECRET_KEY loaded from environment.")

app = Flask(__name__) # Create Flask app instance
app.secret_key = FLASK_SECRET_KEY

# Configure session security
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protect against CSRF (consider 'Strict' for more security)

# CSRF Protection (Example using Flask-WTF)
# csrf = CSRFProtect(app) # Initialize CSRF protection

# Example of using a secrets manager (Conceptual - replace with actual implementation)
# Consider using: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, Google Cloud Secret Manager
# See documentation for each service for specific implementation details.
# def get_secret(secret_name):
#     # Replace with your secrets manager implementation (e.g., AWS Secrets Manager, HashiCorp Vault)
#     try:
#         # Example using a hypothetical secrets manager client
#         secret_value = secrets_manager_client.get_secret(secret_name)
#         return secret_value
#     except Exception as e:
#         logging.error(f"Error retrieving secret {secret_name}: {e}")
#         # Consider raising an exception or returning a default value
#         return None # Or raise an exception: raise Exception(f"Failed to retrieve secret: {secret_name}")

# DATABASE_URL = get_secret("database_url") # Example of using a secrets manager

# Example of Rate Limiting (Conceptual - replace with actual implementation)
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address
# limiter = Limiter(
#     app,
#     key_func=get_remote_address,
#     default_limits=["200 per day", "50 per hour"]
# )

# @app.route("/api/protected")
# @limiter.limit("10 per minute") # Example of limiting a specific route
# def protected_api():
#     return "This is a protected API endpoint"

