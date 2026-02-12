import os
from django.contrib.auth.hashers import make_password
from django.conf import settings  # Import settings to access PASSWORD_HASHERS
import bcrypt  # Required: pip install bcrypt
import logging

logger = logging.getLogger(__name__)

def get_application_password():
    """
    Retrieves the application password from a secure source (e.g., Vault, AWS Secrets Manager).
    This is a placeholder; replace with your actual secret retrieval logic.
    """
    try:
        # Example:  Replace with your actual secret retrieval logic
        password = os.environ.get("MY_APPLICATION_PASSWORD")
        if not password:
            logger.error("Application password not found in environment variable.")
            return None
        return password
    except Exception as e:
        logger.exception("Error retrieving application password:")
        return None


password = get_application_password()

if password:
    # 1. Pre-hash the password from the secure source using bcrypt
    hashed_env_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # 2. Use Django's make_password to hash the pre-hashed password
    hashed_password = make_password(hashed_env_password)

    # Store the hashed_password in your database securely.
    #  - Use a database field designed for storing hashed passwords (e.g., a CharField with a sufficient max_length).
    #  - Ensure the database connection is secure (e.g., using SSL).
    #  - Consider encrypting the database at rest.
    # Do NOT print it to the console in a production environment.
    # print(hashed_password) # Remove this line in production
    print("Password hashed successfully (but not printed for security).")
else:
    print("Error: Could not retrieve application password.")


# Optional: Print the configured password hashers for debugging (remove in production)
if settings.DEBUG:
    print("Configured Password Hashers:", settings.PASSWORD_HASHERS)

