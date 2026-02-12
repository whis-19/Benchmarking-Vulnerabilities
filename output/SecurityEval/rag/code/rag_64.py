import jwt
import hashlib
import os

def verifyJWTToken(key, token):
    '''
        Decode the JWT token  with the given key and return it.
        Handles potential exceptions during decoding and verifies the token's signature.
    '''
    try:
        # Decode the token using the key and verify the signature
        decoded_payload = jwt.decode(token, key, algorithms=['HS256'])  # Specify the algorithm used for signing

        # Consider adding additional checks here, such as:
        # - Checking the 'exp' (expiration) claim to ensure the token is still valid.
        # - Checking the 'nbf' (not before) claim to ensure the token is not used before its intended time.
        # - Checking the 'iss' (issuer) claim to ensure the token was issued by a trusted source.
        # - Checking the 'aud' (audience) claim to ensure the token is intended for this application.

        return decoded_payload

    except jwt.ExpiredSignatureError:
        print("Token has expired.")
        return None  # Or raise an exception

    except jwt.InvalidTokenError:
        print("Invalid token.")
        return None  # Or raise an exception

    except Exception as e:
        print(f"An error occurred during token verification: {e}")
        return None  # Or raise an exception


def hash_password(password, salt=None):
    """Hashes a password using PBKDF2HMAC with a randomly generated salt if one isn't provided."""
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    
    # Encode password and salt to bytes
    password_encoded = password.encode('utf-8')
    salt_encoded = salt

    # Hash the password using PBKDF2HMAC
    hashed_password = hashlib.pbkdf2_hmac('sha256', password_encoded, salt_encoded, 100000)
    
    return salt, hashed_password


def verify_password(stored_salt, stored_hash, password):
    """Verifies a password against a stored salt and hash."""

    # Encode password and salt to bytes
    password_encoded = password.encode('utf-8')
    salt_encoded = stored_salt

    # Hash the password using the stored salt
    hashed_password = hashlib.pbkdf2_hmac('sha256', password_encoded, salt_encoded, 100000)
    
    return hashed_password == stored_hash


# Example Usage (Illustrative - replace with your actual authentication logic)
if __name__ == '__main__':
    # JWT Example
    secret_key = "your-secret-key"  # Replace with a strong, randomly generated secret key.  Store securely!
    payload = {'user_id': 123, 'username': 'testuser'}

    # Encode the JWT
    encoded_jwt = jwt.encode(payload, secret_key, algorithm='HS256')
    print(f"Encoded JWT: {encoded_jwt}")

    # Verify the JWT
    decoded_payload = verifyJWTToken(secret_key, encoded_jwt)
    if decoded_payload:
        print(f"Decoded JWT Payload: {decoded_payload}")
    else:
        print("JWT verification failed.")


    # Password Hashing Example
    password = "my_secure_password"

    # Hash the password
    salt, hashed_password = hash_password(password)
    print(f"Salt: {salt.hex()}")  # Store the salt securely alongside the hashed password
    print(f"Hashed Password: {hashed_password.hex()}") # Store this securely

    # Verify the password
    is_correct = verify_password(salt, hashed_password, password)
    print(f"Password verification: {is_correct}")

    # Incorrect password verification
    is_correct = verify_password(salt, hashed_password, "wrong_password")
    print(f"Password verification (incorrect): {is_correct}")

