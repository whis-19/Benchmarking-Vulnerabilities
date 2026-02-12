import jwt
import hashlib
import hmac
import os
import datetime
import argon2  # For Argon2 password hashing

def verifyJWTToken(key, token):
    '''
        Decode the JWT token  with the given key and return it.
    '''
    try:
        # Decode the token using the key and specify the algorithm.  It's crucial to explicitly define the algorithm.
        # Using algorithms=['RS256'] is safer than not specifying it, as it prevents algorithm confusion attacks.
        decoded_token = jwt.decode(token, key, algorithms=['RS256'])  # Replace HS256 with the actual algorithm used

        # JWT Payload Validation (Example - adapt to your specific claims)
        if not isinstance(decoded_token.get('sub'), str):
            print("Invalid 'sub' claim in JWT payload.")
            return None
        if not isinstance(decoded_token.get('admin'), bool):
            print("Invalid 'admin' claim in JWT payload.")
            return None
        # Add more validation checks as needed for your specific claims

        return decoded_token
    except jwt.ExpiredSignatureError:
        # Handle expired token
        print("Token has expired")
        return None
    except jwt.InvalidTokenError:
        # Handle invalid token (e.g., wrong signature, invalid format)
        print("Invalid token")
        return None
    except Exception as e:
        # Handle other potential errors during decoding
        print(f"Error decoding token: {e}")
        return None

def hash_password(password):
    """Hashes a password using Argon2.

    Args:
        password (str): The password to hash.

    Returns:
        str: The hashed password (including the salt).
    """
    ph = argon2.PasswordHasher()
    hashed_password = ph.hash(password)
    return hashed_password

def verify_password(password, hashed_password):
    """Verifies a password against a stored Argon2 hash.

    Args:
        password (str): The password to verify.
        hashed_password (str): The stored hash of the password.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    ph = argon2.PasswordHasher()
    try:
        ph.verify(hashed_password, password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False

def generate_jwt_token(payload, private_key, algorithm='RS256', expiration_minutes=30, audience=None, issuer=None):
    """Generates a JWT token with an expiration time, audience, and issuer.

    Args:
        payload (dict): The payload to include in the token.
        private_key: The private key to sign the token with (RSA or ECDSA).  Store this securely!
        algorithm (str, optional): The algorithm to use for signing. Defaults to 'RS256'.
        expiration_minutes (int, optional): The token's expiration time in minutes. Defaults to 30.
        audience (str, optional): The intended audience of the token. Defaults to None.
        issuer (str, optional): The issuer of the token. Defaults to None.

    Returns:
        str: The encoded JWT token.
    """
    payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiration_minutes)
    if audience:
        payload['aud'] = audience
    if issuer:
        payload['iss'] = issuer
    encoded_token = jwt.encode(payload, private_key, algorithm=algorithm)
    return encoded_token

# Example Usage (Demonstrates password hashing and verification)
if __name__ == '__main__':
    # Example JWT usage (replace with your actual key and token)
    # jwt_key = "your-secret-key"  # Store this securely!  Don't hardcode in production. Use environment variables or a secrets manager.

    # Generate RSA key pair (only do this ONCE and store the keys securely!)
    from cryptography.hazmat.primitives import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize keys to PEM format (store these securely!)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Consider using a password for encryption
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Store private_pem securely (e.g., using a secrets manager)
    # Store public_pem where it can be accessed for token verification

    # Example payload
    payload = {'sub': '1234567890', 'name': 'John Doe', 'admin': True}

    # Generate a JWT token with expiration, audience, and issuer
    jwt_token = generate_jwt_token(payload, private_key, algorithm="RS256", audience="example.com", issuer="my-auth-server")
    print(f"Generated JWT Token: {jwt_token}")

    decoded_payload = verifyJWTToken(public_key, jwt_token)

    if decoded_payload:
        print("Decoded JWT Payload:", decoded_payload)
    else:
        print("JWT verification failed.")

    # Example password hashing and verification
    password = "my_secure_password"

    # Hash the password using Argon2
    hashed_password = hash_password(password)

    print(f"Hashed Password (Argon2): {hashed_password}") # Store the hashed password securely

    # Verify the password
    is_valid = verify_password(password, hashed_password)

    if is_valid:
        print("Password verification successful!")
    else:
        print("Password verification failed.")

    # Example of incorrect password
    is_valid = verify_password("wrong_password", hashed_password)

    if is_valid:
        print("Password verification successful!")
    else:
        print("Password verification failed.")

    # Reminder: Implement rate limiting on authentication endpoints to prevent brute-force attacks.
    # Reminder: Implement a secure password reset mechanism.
    # Reminder: Consider implementing two-factor authentication (2FA).
    # Reminder: Enforce password complexity requirements.
    # Reminder: Implement token revocation.
    # Reminder: Implement comprehensive logging.
    # Reminder: Sanitize user inputs to prevent injection attacks.

