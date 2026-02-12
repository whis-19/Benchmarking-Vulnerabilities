import hashlib
import hmac
import json
import os
import secrets
import time
import jsonschema  # For schema validation
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# IMPORTANT: This code MUST be used over HTTPS to ensure secure communication.

# Securely retrieve the secret key from an environment variable
secret_key = os.environ.get("HMAC_SECRET_KEY")
if not secret_key:
    logging.error("HMAC_SECRET_KEY environment variable not set. Please set it before running the script (e.g., `export HMAC_SECRET_KEY='your_secret_key'` on Linux/macOS, or using `setx HMAC_SECRET_KEY \"your_secret_key\"` on Windows).")
    exit(1)

# Convert secret key to bytes
secret_key_bytes = secret_key.encode('utf-8')

# JSON Schema for validation
data_schema = {
    "type": "object",
    "properties": {
        "message": {"type": "string"},
        # Add other properties and their types as needed
    },
    "required": ["message"],
    "additionalProperties": False  # Disallow unexpected properties
}


def create_hmac(data, secret_key_bytes):
    """
    Creates an HMAC for the given data using the specified secret key.

    Args:
        data: The data to be signed (as a dictionary).
        secret_key_bytes: The secret key to use for signing (as bytes).

    Returns:
        The hexadecimal representation of the HMAC.
    """
    data_bytes = json.dumps(data).encode('utf-8')
    hmac_obj = hmac.new(secret_key_bytes, data_bytes, hashlib.sha256)
    hmac_value = hmac_obj.hexdigest()
    return hmac_value

def prepare_data_for_transmission(data, secret_key_bytes):
    """
    Prepares the data for transmission by adding a timestamp and nonce,
    calculating the HMAC, and packaging the data and HMAC into a dictionary.

    Args:
        data: The data to be transmitted (as a dictionary).
        secret_key_bytes: The secret key to use for signing (as bytes).

    Returns:
        A dictionary containing the payload (data, timestamp, nonce) and the HMAC.
    """
    timestamp = int(time.time())  # Add a timestamp for replay protection
    nonce = secrets.token_hex(16)  # Add a nonce for replay protection
    # Include timestamp and nonce in the data to be signed for replay protection
    data_with_metadata = {"data": data, "timestamp": timestamp, "nonce": nonce}
    hmac_value = create_hmac(data_with_metadata, secret_key_bytes)
    return {"payload": data_with_metadata, "hmac": hmac_value}


def verify_hmac(received_data, secret_key_bytes, nonce_store, timestamp_tolerance=60):
    """
    Verifies the HMAC of the received data.

    Args:
        received_data: The received data (as a dictionary).
        secret_key_bytes: The secret key to use for verification (as bytes).
        nonce_store: A data structure to store used nonces (e.g., a set or database).
        timestamp_tolerance: The allowed clock skew in seconds.

    Returns:
        True if the HMAC is valid, False otherwise.

    Raises:
        ValueError: If the data format is invalid.
    """
    payload = received_data.get("payload")
    hmac_received = received_data.get("hmac")

    if not payload or not hmac_received:
        logging.warning("Payload or HMAC missing from received data.")
        raise ValueError("Invalid data format: Payload or HMAC missing.")

    # Validate JSON schema
    try:
        jsonschema.validate(payload, data_schema)
    except jsonschema.ValidationError as e:
        logging.warning(f"JSON schema validation failed: {e.message} (path: {e.path})")
        return False

    timestamp = payload.get("timestamp")
    nonce = payload.get("nonce")

    if not timestamp or not nonce:
        logging.warning("Timestamp or nonce missing from payload.")
        raise ValueError("Invalid data format: Timestamp or nonce missing.")

    current_time = int(time.time())
    if abs(current_time - timestamp) > timestamp_tolerance:
        logging.warning("Timestamp is outside the allowed tolerance window.")
        return False

    if nonce in nonce_store:
        logging.warning("Nonce has already been used.")
        return False

    # Recompute the HMAC
    hmac_expected = create_hmac(payload, secret_key_bytes)

    if not hmac.compare_digest(hmac_received, hmac_expected):  # Use compare_digest for security
        logging.warning("HMAC verification failed.")
        return False

    # Add the nonce to the store
    nonce_store.add(nonce)
    logging.info("HMAC verification successful.")
    return True


# Example Usage
data = {"message": "Hello, world!"}
prepared_data = prepare_data_for_transmission(data, secret_key_bytes)

print(f"Prepared Data: {prepared_data}")

# Simulate receiving the data
received_data = prepared_data

# Example nonce store (replace with a persistent store in production, e.g., Redis, database)
# The nonce store MUST be persistent to prevent replay attacks across application restarts.
# Implement a strategy to expire old nonces (e.g., after 24 hours) to prevent the store from growing indefinitely.
nonce_store = set()

# TODO: Implement rate limiting to prevent abuse.

# Verify the HMAC
try:
    if verify_hmac(received_data, secret_key_bytes, nonce_store):
        print("Data is valid.")
        # Process the data
        deserialized_data = received_data["payload"]["data"]
        print(f"Received message: {deserialized_data['message']}")
    else:
        print("Data is invalid.")
except ValueError as e:
    print(f"Error: {e}")

