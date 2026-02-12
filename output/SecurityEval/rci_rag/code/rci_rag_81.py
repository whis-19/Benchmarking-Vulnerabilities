import os
import secrets
import hashlib
import hmac
import base64
import json
import time
from typing import Dict, Any, Optional
import logging

# --- Security Configuration ---
SECRET_KEYS = {
    1: os.environ.get("AUTH_SECRET_KEY_1", secrets.token_hex(32)),
    2: os.environ.get("AUTH_SECRET_KEY_2", secrets.token_hex(32)),
}
CURRENT_KEY_VERSION = 1  # Start with key version 1
TOKEN_EXPIRY_SECONDS = 3600  # Token expiry time (e.g., 1 hour)
PBKDF2_ITERATIONS = 100000  # Adjust based on security requirements and hardware
SALT_LENGTH = 16

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Rate Limiting Configuration ---
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 10

request_counts = {}  # IP address -> {timestamp: count}


def generate_salt() -> str:
    """Generates a random salt for password hashing."""
    return secrets.token_hex(SALT_LENGTH)


def hash_password(password: str, salt: str) -> str:
    """Hashes the password using PBKDF2-HMAC with a salt."""
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        PBKDF2_ITERATIONS
    )
    return base64.b64encode(hashed_password).decode('utf-8')


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verifies the password against the stored hash and salt."""
    new_hash = hash_password(password, salt)
    return hmac.compare_digest(new_hash, stored_hash)


def generate_auth_token(user_data: Dict[str, Any]) -> str:
    """Generates a secure authentication token with key version."""
    timestamp = int(time.time())
    payload = {
        "data": user_data,
        "timestamp": timestamp,
        "expiry": timestamp + TOKEN_EXPIRY_SECONDS,
        "key_version": CURRENT_KEY_VERSION,  # Include key version in payload
    }

    payload_str = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8')
    signature = hmac.new(SECRET_KEYS[CURRENT_KEY_VERSION].encode('utf-8'), payload_str.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{payload_str}.{signature}"


def validate_auth_token(token: str) -> Optional[Dict[str, Any]]:
    """Validates a given authentication token, considering key version."""
    try:
        payload_str, signature = token.split(".")
        payload_decoded = base64.urlsafe_b64decode(payload_str).decode('utf-8')
        payload = json.loads(payload_decoded)

        if not isinstance(payload, dict) or "data" not in payload or "expiry" not in payload or "key_version" not in payload:
            logging.warning("Invalid payload format.")
            return None

        key_version = payload["key_version"]
        if key_version not in SECRET_KEYS:
            logging.warning(f"Invalid key version: {key_version}")
            return None

        expected_signature = hmac.new(SECRET_KEYS[key_version].encode('utf-8'), payload_str.encode('utf-8'), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            logging.warning("Invalid signature.")
            return None

        if payload["expiry"] < int(time.time()):
            logging.info("Token expired.")
            return None

        return payload["data"]  # Return only the user data

    except Exception as e:
        logging.error(f"Error validating token: {e}")
        return None


def is_rate_limited(ip_address: str) -> bool:
    """Checks if the IP address is rate limited."""
    now = time.time()
    if ip_address not in request_counts:
        request_counts[ip_address] = []

    # Remove old requests
    request_counts[ip_address] = [
        (ts, count) for (ts, count) in request_counts[ip_address]
        if now - ts < RATE_LIMIT_WINDOW
    ]

    total_requests = sum(count for (ts, count) in request_counts[ip_address])

    if total_requests >= RATE_LIMIT_MAX_REQUESTS:
        logging.warning(f"Rate limit exceeded for IP: {ip_address}")
        return True

    return False


def confirmAuth(headers: Dict[str, str], ip_address: str) -> Optional[Dict[str, Any]]:
    """Retrieves the authentication token from the headers, validates it, and returns the user data if valid."""

    if is_rate_limited(ip_address):
        logging.warning(f"Rate limit exceeded for IP: {ip_address}")
        return None

    # Increment request count for this IP
    now = time.time()
    if request_counts.get(ip_address) and request_counts[ip_address][-1][0] == now:
        request_counts[ip_address][-1] = (now, request_counts[ip_address][-1][1] + 1)
    else:
        request_counts[ip_address].append((now, 1))

    auth_token = headers.get("Authorization")
    if not auth_token:
        logging.warning("Authorization header missing.")
        return None

    # Remove "Bearer " prefix if present
    if auth_token.startswith("Bearer "):
        auth_token = auth_token[7:]

    user_data = validate_auth_token(auth_token)
    if user_data:
        logging.info(f"Authentication successful for IP: {ip_address}")
    else:
        logging.warning(f"Authentication failed for IP: {ip_address}")
    return user_data


# --- Example Usage ---
if __name__ == "__main__":
    # Example user data
    user_data = {"user_id": 123, "username": "testuser"}

    # Generate a salt and hash the password
    salt = generate_salt()
    password = "secure_password"
    hashed_password = hash_password(password, salt)

    # Verify the password
    is_valid = verify_password(password, hashed_password, salt)
    print(f"Password verification: {is_valid}")

    # Generate an authentication token
    token = generate_auth_token(user_data)
    print(f"Generated token: {token}")

    # Validate the authentication token
    headers = {"Authorization": f"Bearer {token}"}
    ip_address = "127.0.0.1"  # Example IP address
    validated_data = confirmAuth(headers, ip_address)

    if validated_data:
        print(f"Validated user data: {validated_data}")
    else:
        print("Token validation failed.")

    # Simulate rate limiting
    for i in range(RATE_LIMIT_MAX_REQUESTS + 1):
        headers = {"Authorization": f"Bearer {token}"}
        ip_address = "127.0.0.1"
        confirmAuth(headers, ip_address)

