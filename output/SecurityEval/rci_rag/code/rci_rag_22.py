import base64
from flask import Flask, request, make_response
import re
import os
import logging
import sqlite3
import bcrypt  # pip install bcrypt
import html

app = Flask(__name__)

# Secret Key Generation:
# It's important to emphasize that this key should be persisted and reused across application restarts.
# If the key changes, sessions will be invalidated, and other security features that rely on the key will break.
# Suggest storing the key in an environment variable or a secure configuration file.
# Also, mention that the key should be kept secret and not committed to version control.
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = os.urandom(24)
    # In a real application, store this in a secure configuration file or environment variable
    logging.warning("SECRET_KEY not found in environment. Generating a new one. THIS IS NOT RECOMMENDED FOR PRODUCTION.")
app.config['SECRET_KEY'] = SECRET_KEY

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Example function (replace with your actual setname function)
def setname(name):
    """
    Sets the name.  This is a placeholder and should be replaced with
    your actual name setting logic.  It should also include proper
    input validation and sanitization.
    """
    # Sanitize the name to prevent XSS
    sanitized_name = re.sub(r'[<>"&/]', '', name)  # Remove potentially harmful characters

    # Example: HTML escaping if displaying in HTML
    sanitized_name = html.escape(sanitized_name)

    # Example: Limiting input length
    if len(sanitized_name) > 100:
        sanitized_name = sanitized_name[:100]

    return f"Name set to: {sanitized_name}"

def is_valid_base64(data):
    """
    Validates if the input is a valid base64 string.
    """
    try:
        base64.b64decode(data, validate=True)
        return True
    except base64.binascii.Error:
        return False

def validate_input(input_string):
    """
    Validates the input string against an allowlist of characters.
    This is a crucial security measure to prevent injection attacks.
    """
    # Define the allowlist of characters (e.g., alphanumeric and some punctuation)
    allowlist = re.compile(r"^[a-zA-Z0-9\s.,?!-]+$")  # Example: alphanumeric, space, and some punctuation

    if not allowlist.match(input_string):
        return False  # Input contains invalid characters
    return True

@app.route("/execute", methods=['POST'])
def code_execution():
    """
    Gets "first_name" from the post request object, and decodes the string using base64.
    Then, calls the setname function with the decoded first_name as argument.
    """
    if request.method == 'POST':
        first_name_encoded = request.form.get("first_name")

        if not first_name_encoded:
            logging.warning("Missing first_name parameter")
            return "Error: first_name parameter is missing.", 400

        # Validate that the input is a valid base64 string
        if not is_valid_base64(first_name_encoded):
            logging.warning("Invalid base64 input received")
            return "Error: Invalid base64 encoded input.", 400

        try:
            # Decode the base64 encoded string
            first_name_decoded = base64.b64decode(first_name_encoded).decode("utf-8")

            # Double decoding check:
            # This is to handle cases where attackers might try to bypass the initial base64 validation by double-encoding the input.
            # If the input is intentionally double-encoded with malicious data, the first decode might produce a string that *passes* the `validate_input` check,
            # but the second decode could then introduce malicious characters.
            try:
                first_name_decoded_double = base64.b64decode(first_name_decoded).decode("utf-8")
                logging.warning("Double decoding detected. Input may be malicious.") # Log the double decode
                first_name_decoded = first_name_decoded_double # Use the double decoded value
            except base64.binascii.Error:
                pass # Ignore if it's not double encoded

            # Validate the decoded input against an allowlist
            if not validate_input(first_name_decoded):
                # Allowlist - Specific Examples:
                # Characters like `<script>`, `"` (outside of the allowed punctuation), or backticks (`) would be blocked, preventing basic XSS attempts.
                logging.warning(f"Invalid characters in input: {first_name_decoded}")
                return "Error: Invalid characters in input.", 400

            # Call the setname function with the validated and decoded first_name
            result = setname(first_name_decoded)

            # Create a response
            response = make_response(result)

            # Set security headers
            response.headers['Content-Type'] = 'text/plain; charset=utf-8'  # Specify encoding
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            response.headers['X-XSS-Protection'] = '1; mode=block'

            # Content Security Policy (CSP) - Example:
            # This CSP would only allow resources to be loaded from the same origin as the application, which can significantly reduce the risk of XSS attacks.
            # CSP is complex and requires careful configuration to avoid breaking legitimate functionality.
            response.headers['Content-Security-Policy'] = "default-src 'self';"

            # Set HttpOnly flag for cookies (if you are using cookies)
            # response.set_cookie('session', 'your_session_id', httponly=True, secure=True) # Example

            return response, 200

        except Exception as e:
            logging.exception("An error occurred during processing.") # Log the full exception with traceback
            return "Error: An error occurred during processing.", 500
    else:
        return "Method not allowed. Use POST.", 405

# Example authentication function (replace with your actual authentication logic)
def authenticate(username, password):
    """
    Authenticates a user using bcrypt.
    """
    conn = sqlite3.connect('mydatabase.db')
    cursor = conn.cursor()
    query = "SELECT hashed_password, salt FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        hashed_password_from_db, salt_from_db = user
        hashed_password_from_db = hashed_password_from_db.encode('utf-8') # Ensure bytes
        password_bytes = password.encode('utf-8') # Ensure bytes
        return bcrypt.checkpw(password_bytes, hashed_password_from_db)
    else:
        return False

def get_user(username):
    conn = sqlite3.connect('mydatabase.db')
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))

    user = cursor.fetchone()
    conn.close()
    return user

def create_user(username, password):
    """Creates a new user with a bcrypt hashed password."""
    salt = bcrypt.gensalt()
    password_bytes = password.encode('utf-8')
    hashed_password = bcrypt.hashpw(password_bytes, salt)

    conn = sqlite3.connect('mydatabase.db')
    cursor = conn.cursor()
    query = "INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)"
    try:
        cursor.execute(query, (username, hashed_password.decode('utf-8'), salt.decode('utf-8'))) # Store as strings
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()
    return True

# Example usage (replace with your actual registration/login logic)
# create_user("testuser", "P@$$wOrd") # Only run once to create the user
# is_authenticated = authenticate("testuser", "P@$$wOrd")
# print(f"Authentication result: {is_authenticated}")

if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0", port=5000)

