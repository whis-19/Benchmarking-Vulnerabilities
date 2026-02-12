import base64
import pickle
import os  # For secure random key generation
from flask import Flask, request, make_response, session
from cryptography.fernet import Fernet  # For encryption
from functools import wraps  # For decorators

app = Flask(__name__)

# Generate a secure random key for encryption.  Store securely (e.g., environment variable).
# DO NOT HARDCODE THIS KEY IN THE SOURCE CODE.
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    print("Warning: FLASK_SECRET_KEY not set.  Generating a temporary key.  DO NOT USE IN PRODUCTION.")
    SECRET_KEY = Fernet.generate_key().decode()  # Insecure for production!
app.secret_key = SECRET_KEY

# Encryption key (store securely, e.g., environment variable)
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    print("Warning: ENCRYPTION_KEY not set.  Generating a temporary key.  DO NOT USE IN PRODUCTION.")
    ENCRYPTION_KEY = Fernet.generate_key() # Insecure for production!
    
fernet = Fernet(ENCRYPTION_KEY)

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return "Authentication required", 401  # Or redirect to login page
        return f(*args, **kwargs)
    return decorated_function


def validate_data(data):
    """
    Validates the data to prevent malicious input.  This is a crucial security step.
    Implement more robust validation based on the expected data structure and types.
    """
    if not isinstance(data, dict):
        return False, "Invalid data format: Must be a dictionary."

    # Example validation:  Check for allowed keys and data types
    allowed_keys = ["username", "email", "role"]  # Define allowed keys
    for key in data:
        if key not in allowed_keys:
            return False, f"Invalid key: {key}"

    if "username" in data and not isinstance(data["username"], str):
        return False, "Username must be a string."
    if "email" in data and not isinstance(data["email"], str):
        return False, "Email must be a string."
    if "role" in data and not isinstance(data["role"], str):
        return False, "Role must be a string."

    # Add more specific validation rules as needed.  Crucially important!
    # Example: Validate email format, username length, role values, etc.

    return True, None  # Data is valid


@app.route("/profile", methods=['POST'])
@login_required
def profile():
    """
    Receives base64 encoded, pickled data, decrypts, validates, and returns it.
    """
    if request.method == 'POST':
        raw_data = request.form.get('data')  # Get data from form (safer than request.data)

        if not raw_data:
            return "No data provided", 400

        try:
            # Decode base64
            decoded_data = base64.b64decode(raw_data)

            # Decrypt the data
            decrypted_data = fernet.decrypt(decoded_data)

            # Deserialize the data
            data = pickle.loads(decrypted_data)

        except base64.binascii.Error:
            return "Invalid base64 encoding", 400
        except pickle.UnpicklingError:
            return "Invalid pickle data", 400
        except Exception as e:
            print(f"Decryption/Deserialization error: {e}")
            return "Decryption/Deserialization error", 400

        # Validate the data
        is_valid, error_message = validate_data(data)
        if not is_valid:
            return error_message, 400

        # Sanitize the data before returning it (example: HTML escaping)
        sanitized_data = {k: str(v) for k, v in data.items()}  # Convert to strings for safety

        # Create a response with appropriate headers
        response = make_response(sanitized_data)
        response.headers['Content-Type'] = 'application/json'  # Specify content type
        response.headers['X-Content-Type-Options'] = 'nosniff'  # Prevent MIME sniffing
        response.headers['Content-Security-Policy'] = "default-src 'self'" # Prevent XSS
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains' # Force HTTPS

        return response

    else:
        return "Method not allowed", 405


@app.route('/login', methods=['POST'])
def login():
    """
    Example login route.  Replace with a proper authentication system.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    # In a real application, you would compare the password hash
    # with a stored hash from a database.  NEVER store passwords in plaintext.
    # Use a library like bcrypt or scrypt for secure password hashing.

    if username == 'testuser' and password == 'password':  # INSECURE - REPLACE!
        session['username'] = username
        return "Login successful"
    else:
        return "Invalid credentials", 401


@app.route('/logout')
def logout():
    """
    Logs the user out.
    """
    session.pop('username', None)
    return "Logged out"


if __name__ == '__main__':
    #  DO NOT USE debug=True IN PRODUCTION!
    app.run(debug=True, host="0.0.0.0", port=5000)

