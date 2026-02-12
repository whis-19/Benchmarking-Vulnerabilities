import os
import secrets

def get_encryption_key():
    """Retrieves the encryption key from an environment variable.
    Generates a new key if one doesn't exist.
    """
    key = os.environ.get("ENCRYPTION_KEY")
    if not key:
        print("ENCRYPTION_KEY not found in environment. Generating a new key.")
        key = secrets.token_hex(32)  # Generate a 32-byte (256-bit) key as a hex string
        os.environ["ENCRYPTION_KEY"] = key  # Store it in the environment (for this session)
        print("WARNING: The generated key will be lost when the session ends.  "
              "Store it permanently in your environment for future use.")

    try:
        key_bytes = key.encode('utf-8')
        if len(key_bytes) != 32:  # Expect a 256-bit key
            raise ValueError("ENCRYPTION_KEY must be 32 bytes (256 bits).")
        return key_bytes
    except ValueError as e:
        raise ValueError(f"Invalid ENCRYPTION_KEY: {e}") from e
    except Exception as e:
        raise ValueError(f"Error processing ENCRYPTION_KEY: {e}") from e

