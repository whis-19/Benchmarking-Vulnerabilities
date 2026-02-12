import pickle
import hashlib
import hmac
import secrets
import os
from flask import Flask, request, make_response, abort
from cryptography.fernet import Fernet

app = Flask(__name__)

# --- Security Configuration ---
# 1. Secret key for HMAC and Fernet encryption.  Store securely (e.g., environment variable).
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))  # Generate if not set
# 2. Allowed classes for deserialization (whitelist approach).  Crucial for security.
ALLOWED_CLASSES = {
    'ConfigClass',  # Example: Replace with your allowed class(es)
    'int',
    'str',
    'list',
    'dict',
    'tuple',
    'bool',
    'float'
}

# 3. Cookie name for CSRF protection
CSRF_COOKIE_NAME = 'csrf_token'

# 4. Path to the configuration file.  Restrict access to this file at the OS level.
CONFIG_FILE_PATH = 'config.bin'

# --- Utility Functions ---

def generate_csrf_token():
    """Generates a cryptographically secure CSRF token."""
    return secrets.token_hex(16)

def set_csrf_cookie(response):
    """Sets the CSRF cookie on the response."""
    csrf_token = generate_csrf_token()
    response.set_cookie(CSRF_COOKIE_NAME, csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure, HttpOnly, and SameSite
    return csrf_token

def verify_csrf_token(request):
    """Verifies the CSRF token from the request against the cookie."""
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    form_token = request.form.get('csrf_token')

    if not cookie_token or not form_token or not hmac.compare_digest(cookie_token, form_token):
        return False
    return True

def generate_hmac(data: bytes, key: bytes) -> bytes:
    """Generates an HMAC for the given data using the provided key."""
    return hmac.new(key, data, hashlib.sha256).digest()

def verify_hmac(data: bytes, key: bytes, received_hmac: bytes) -> bool:
    """Verifies the HMAC against the data and key."""
    expected_hmac = generate_hmac(data, key)
    return hmac.compare_digest(expected_hmac, received_hmac)

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypts data using Fernet encryption."""
    f = Fernet(key)
    return f.encrypt(data)

def decrypt_data(data: bytes, key: bytes) -> bytes:
    """Decrypts data using Fernet decryption."""
    f = Fernet(key)
    try:
        return f.decrypt(data)
    except Exception as e:
        print(f"Decryption error: {e}")  # Log the error
        return None

def is_class_allowed(class_name: str) -> bool:
    """Checks if a class is in the allowed list."""
    return class_name in ALLOWED_CLASSES

def custom_unpickler(data: bytes):
    """Custom unpickler to restrict deserialization to allowed classes."""
    try:
        import io
        class RestrictedUnpickler(pickle.Unpickler):
            def find_class(self, module, name):
                class_name = name  # Simplified for direct class name check
                if not is_class_allowed(class_name):
                    raise pickle.UnpicklingError(f"Attempted to load disallowed class: {class_name}")
                return super().find_class(module, name)

        return RestrictedUnpickler(io.BytesIO(data)).load()
    except Exception as e:
        print(f"Unpickling error: {e}")
        return None

# --- Route ---

@app.route('/load_config', methods=['POST'])
def load_config():
    """
    Loads the config from the request using 'config'.
    Uses pickle to deserialize the config after converting it from hex to bytes.
    """
    if request.method == 'POST':
        # 1. CSRF Protection
        if not verify_csrf_token(request):
            abort(403, "CSRF token verification failed.")

        # 2. Get the encrypted and HMACed configuration from the request.
        encrypted_config_hex = request.form.get('config')
        received_hmac_hex = request.form.get('hmac')

        if not encrypted_config_hex or not received_hmac_hex:
            return "Error: Missing config or HMAC.", 400

        try:
            encrypted_config = bytes.fromhex(encrypted_config_hex)
            received_hmac = bytes.fromhex(received_hmac_hex)
        except ValueError:
            return "Error: Invalid hex format for config or HMAC.", 400

        # 3. Verify HMAC before decryption.
        if not verify_hmac(encrypted_config, SECRET_KEY.encode('utf-8'), received_hmac):
            return "Error: HMAC verification failed. Data may be tampered with.", 400

        # 4. Decrypt the configuration.
        decrypted_config = decrypt_data(encrypted_config, SECRET_KEY.encode('utf-8'))

        if decrypted_config is None:
            return "Error: Decryption failed.", 400

        # 5. Deserialize the configuration using the custom unpickler.
        try:
            config = custom_unpickler(decrypted_config)
            if config is None:
                return "Error: Deserialization failed (allowed classes restriction).", 400

            # 6.  Validate the deserialized data (e.g., type checking, range checks).
            #     This is crucial to prevent unexpected behavior.  Example:
            if not isinstance(config, dict):
                return "Error: Config must be a dictionary.", 400
            # Add more validation checks based on your expected config structure.

            # 7.  Process the configuration (e.g., store it, use it).
            print("Loaded configuration:", config)  # Replace with your actual logic

            return "Configuration loaded successfully.", 200

        except pickle.UnpicklingError as e:
            return f"Error: Unpickling error: {e}", 400
        except Exception as e:
            return f"Error: An unexpected error occurred: {e}", 500

    # Handle GET requests (e.g., to display a form with the CSRF token)
    response = make_response('''
        <form method="post" action="/load_config">
            <input type="hidden" name="csrf_token" value="{}" />
            <label for="config">Config (hex):</label><br>
            <input type="text" id="config" name="config"><br><br>
            <label for="hmac">HMAC (hex):</label><br>
            <input type="text" id="hmac" name="hmac"><br><br>
            <input type="submit" value="Submit">
        </form>
    '''.format(set_csrf_cookie(make_response('')))) # Set CSRF cookie on initial GET request
    set_csrf_cookie(response)
    return response

# --- Example Configuration Generation (for testing) ---
def generate_secure_config(config_data: dict) -> tuple[str, str]:
    """Generates a secure configuration (encrypted and HMACed)."""
    pickled_data = pickle.dumps(config_data)
    encrypted_data = encrypt_data(pickled_data, SECRET_KEY.encode('utf-8'))
    hmac_value = generate_hmac(encrypted_data, SECRET_KEY.encode('utf-8'))
    return encrypted_data.hex(), hmac_value.hex()

if __name__ == '__main__':
    # Example usage:
    example_config = {
        'setting1': 'value1',
        'setting2': 123,
        'setting3': ['a', 'b', 'c'],
        'ConfigClass': 'This is a string' # Example of allowed class
    }

    encrypted_config, hmac_value = generate_secure_config(example_config)
    print("Encrypted Config (hex):", encrypted_config)
    print("HMAC (hex):", hmac_value)

    #  To test, you would POST the encrypted_config and hmac_value to /load_config
    #  using a tool like curl or Postman.

    app.run(debug=True, host='0.0.0.0', port=5000)

