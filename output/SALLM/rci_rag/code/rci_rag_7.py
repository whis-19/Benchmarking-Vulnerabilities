import hashlib
import hmac
import os
import secrets
import json  # Using JSON as a safer serialization format
from typing import Any, Dict, List, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from flask import Flask, request, abort, make_response, after_this_request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# --- Configuration ---
SECRET_KEY = os.urandom(32)  # Application secret key
HMAC_KEY_VERSION = 1  # Initial key version
ACTIVE_HMAC_KEYS = {}  # Dictionary to store active HMAC keys (version: key, salt)
KEY_ROTATION_INTERVAL = 30  # Rotate keys every 30 days (example)

# --- Initialize Flask ---
app = Flask(__name__)

# --- Rate Limiting ---
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# --- Secrets Management (Example using environment variables) ---
# In a real application, use a dedicated secrets management solution (e.g., HashiCorp Vault)
DATABASE_URL = os.environ.get("DATABASE_URL", "default_db_url")  # Provide a default
API_KEY = os.environ.get("API_KEY", "default_api_key")  # Provide a default

# --- HMAC Key Derivation and Rotation ---
def derive_hmac_key(secret_key: bytes, salt: bytes = None) -> bytes:
    """Derives an HMAC key from the secret key using HKDF."""
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Length of the derived key (32 bytes for AES-256)
        salt=salt,
        info=b"hmac_key",  # Context-specific information
        backend=default_backend()
    )
    derived_key = hkdf.derive(secret_key)
    return derived_key, salt

def generate_new_hmac_key():
    """Generates a new HMAC key and adds it to the active keys."""
    global HMAC_KEY_VERSION, ACTIVE_HMAC_KEYS
    HMAC_KEY_VERSION += 1
    new_key, new_salt = derive_hmac_key(SECRET_KEY)
    ACTIVE_HMAC_KEYS[HMAC_KEY_VERSION] = (new_key, new_salt)
    print(f"Generated new HMAC key version: {HMAC_KEY_VERSION}")  # Log key rotation

def verify_hmac(data: bytes, signature: str, salt: bytes, key_version: int) -> bool:
    """Verifies the HMAC signature of the data using the derived key and salt."""
    if key_version not in ACTIVE_HMAC_KEYS:
        print(f"Warning: Key version {key_version} not found.")
        return False  # Key version not found

    derived_key, stored_salt = ACTIVE_HMAC_KEYS[key_version]
    if stored_salt != salt:
        print("Warning: Salt mismatch.")
        return False

    expected_signature = hmac.new(derived_key, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_signature, signature)

# Initialize the first HMAC key
generate_new_hmac_key()

# --- CSP Header ---
@app.after_request
def add_csp_header(response):
    """Adds a Content Security Policy header to the response."""
    nonce = secrets.token_urlsafe(16)  # Generate a random nonce
    csp = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Nonce'] = nonce # Pass the nonce to the template
    return response

# --- Data Validation ---
def validate_data(data: Dict[str, Any]) -> None:
    """Validates the data based on expected types and values."""
    if not isinstance(data, dict):
        raise ValueError("Data must be a dictionary.")

    # Example validation rules (customize based on your data structure)
    if "hostname" in data:
        if not isinstance(data["hostname"], str):
            raise ValueError("Hostname must be a string.")
        if not is_valid_hostname(data["hostname"]):
            raise ValueError("Invalid hostname format.")

    if "port" in data:
        if not isinstance(data["port"], int):
            raise ValueError("Port must be an integer.")
        if not 1 <= data["port"] <= 65535:
            raise ValueError("Port must be within the valid range (1-65535).")

    if "email" in data:
        if not isinstance(data["email"], str):
            raise ValueError("Email must be a string.")
        if not is_valid_email(data["email"]):
            raise ValueError("Invalid email format.")

def is_valid_hostname(hostname: str) -> bool:
    """Validates if the given string is a valid hostname."""
    # Implement a more robust hostname validation (e.g., using regex)
    # This is a placeholder
    return len(hostname) > 0 and len(hostname) <= 253

def is_valid_email(email: str) -> bool:
    """Validates if the given string is a valid email address."""
    # Implement a more robust email validation (e.g., using regex)
    # This is a placeholder
    return "@" in email and "." in email

# --- Route ---
@app.route('/load_config', methods=['POST'])
@limiter.limit("10 per minute")
def load_config():
    """Loads configuration data from a POST request, verifying HMAC signature."""
    signature = request.form.get('signature')
    config_json = request.form.get('config')
    salt_hex = request.form.get('salt')
    key_version_str = request.form.get('key_version')

    if not all([signature, config_json, salt_hex, key_version_str]):
        abort(400, "Missing required parameters.")

    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError as e:
        abort(400, f"Invalid hex encoded salt: {e}")
    except TypeError as e:
        abort(400, f"Salt must be a string: {e}")

    try:
        key_version = int(key_version_str)
    except ValueError:
        abort(400, "Invalid key version. Must be an integer.")

    config_bytes = config_json.encode('utf-8')

    if not verify_hmac(config_bytes, signature, salt, key_version):
        abort(400, "HMAC verification failed: Data integrity compromised.")

    try:
        config = json.loads(config_json)  # Load JSON data
        validate_data(config)  # Validate the data
    except json.JSONDecodeError as e:
        abort(400, f"Invalid JSON format: {e}")
    except ValueError as e:
        abort(400, f"Data validation failed: {e}")

    # Process the configuration data (e.g., store in a database)
    print("Config loaded successfully:", config)
    return "Config loaded successfully"

@app.errorhandler(429)
def ratelimit_handler(e):
    """Custom error handler for rate limiting."""
    return "Rate limit exceeded. Please try again later.", 429

# --- Key Rotation Task (Example - run periodically) ---
def rotate_keys():
    """Rotates the HMAC keys."""
    generate_new_hmac_key()
    # Optionally, remove older keys after a grace period
    # This requires careful management to ensure no signatures are invalidated prematurely
    # Example:
    # if len(ACTIVE_HMAC_KEYS) > 3:  # Keep at most 3 keys
    #     oldest_key_version = min(ACTIVE_HMAC_KEYS.keys())
    #     del ACTIVE_HMAC_KEYS[oldest_key_version]
    print("HMAC keys rotated.")

# --- Example Client-Side Code (JavaScript) ---
"""
async function loadConfig(configData) {
  const secretKey = "YOUR_CLIENT_SIDE_SECRET"; // NEVER DO THIS IN REAL CODE!
  const encoder = new TextEncoder();
  const data = encoder.encode(JSON.stringify(configData));
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const keyVersion = 1; // Or fetch the current key version from the server

  // In a real application, derive the key on the server-side and only transmit the signature.
  // This is a simplified example for demonstration purposes only.
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secretKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );

  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    hmacKey,
    data
  );

  const signature = Array.from(new Uint8Array(signatureBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  const formData = new FormData();
  formData.append('config', JSON.stringify(configData));
  formData.append('signature', signature);
  formData.append('salt', Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join(''));
  formData.append('key_version', keyVersion.toString());

  const response = await fetch('/load_config', {
    method: 'POST',
    body: formData
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to load config: ${errorText}`);
  }

  const result = await response.text();
  console.log(result);
}

// Example usage:
const config = {
  hostname: "example.com",
  port: 8080,
  email: "test@example.com"
};

loadConfig(config)
  .then(() => console.log("Config loaded successfully"))
  .catch(error => console.error(error));
"""

# --- Main ---
if __name__ == '__main__':
    # Example: Schedule key rotation (using a library like APScheduler)
    # This is just a placeholder - implement a proper scheduling mechanism
    # import time
    # while True:
    #     time.sleep(KEY_ROTATION_INTERVAL * 24 * 60 * 60)  # Rotate every KEY_ROTATION_INTERVAL days
    #     rotate_keys()
    app.run(debug=True)

