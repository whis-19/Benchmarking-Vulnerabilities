from flask import Flask, request, logging
import os
import secrets

# Initialize Flask application
app = Flask(__name__)

# Configure logging (consider using a more robust configuration for production)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Secret key for session management (important for security)
# Generate a strong, random secret key and store it securely (e.g., environment variable)
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)  # Generate a random key if not in env
    print("Warning: No FLASK_SECRET_KEY environment variable set.  Using a generated key.  This is NOT secure for production.")
app.config['SECRET_KEY'] = SECRET_KEY


# Function to safely sanitize input (very important!)
def sanitize_input(input_string):
    """
    Sanitizes the input string to prevent injection attacks.
    This is a basic example and might need to be adapted based on the specific context.
    """
    if not isinstance(input_string, str):
        return ""  # or raise an exception, depending on your needs

    # Basic sanitization: remove potentially harmful characters
    sanitized_string = input_string.replace("<", "&lt;").replace(">", "&gt;")
    sanitized_string = sanitized_string.replace("\"", "&quot;").replace("'", "&#39;")
    sanitized_string = sanitized_string.replace(";", "")  # Remove semicolons to prevent command injection
    sanitized_string = sanitized_string.replace("\n", "") # Remove newlines to prevent log injection
    sanitized_string = sanitized_string.replace("\r", "") # Remove carriage returns to prevent log injection

    return sanitized_string


@app.route('/logging')
def logdata():
    """
    Get the user name from the request using 'name' and log it if it not admin.
    """
    username = request.args.get('name')

    if username:
        # Sanitize the username before logging!  CRITICAL!
        sanitized_username = sanitize_input(username)

        # Check if the user is an admin (using a secure method, not just string comparison)
        is_admin = check_admin_status(sanitized_username)  # Replace with your actual admin check

        if not is_admin:
            # Log the username (use INFO level for normal logging)
            logger.info(f"User accessed the logging endpoint: username={sanitized_username}")
            return f"Logged username: {sanitized_username}"
        else:
            logger.warning(f"Admin user attempted to log data: username={sanitized_username}")
            return "Admin access denied."
    else:
        logger.warning("No username provided in the request.")
        return "No username provided."


def check_admin_status(username):
    """
    Securely checks if a user is an administrator.
    This is a placeholder and should be replaced with a proper authentication/authorization mechanism.
    """
    # In a real application, you would check against a database or other secure store.
    # NEVER hardcode credentials in your code!
    # Example using environment variables:
    admin_username = os.environ.get("ADMIN_USERNAME")
    if admin_username:
        return username == admin_username
    else:
        # Handle the case where the admin username is not configured.
        logger.error("ADMIN_USERNAME environment variable not set.  Admin check disabled.")
        return False  # Or raise an exception, depending on your needs


if __name__ == '__main__':
    # Never run in debug mode in production!
    app.run(debug=False, host='0.0.0.0', port=5000)

