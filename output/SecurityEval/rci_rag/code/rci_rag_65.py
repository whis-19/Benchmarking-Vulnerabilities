import logging
import os
import secrets
from datetime import timedelta
import jwt  # PyJWT
import hashlib
import base64

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALGORITHM = os.environ.get("JWT_ALGORITHM", 'RS256')  # Default to RS256
TOKEN_EXPIRATION_TIME = int(os.environ.get("JWT_EXPIRATION_MINUTES", 30))
TOKEN_EXPIRATION = timedelta(minutes=TOKEN_EXPIRATION_TIME)

# --- Role-based Access Control (RBAC) ---
ROLES = {
    "admin": {"permissions": ["read", "write", "delete"]},
    "user": {"permissions": ["read"]},
    "guest": {"permissions": ["read"]}
}

# --- JWT Key Management ---

def get_jwt_key(algorithm=ALGORITHM):
    """Retrieves the appropriate key based on the algorithm."""
    if algorithm == 'RS256':
        # Load RSA private key from secure storage (KMS, Vault, etc.)
        try:
            private_key_pem = os.environ.get("JWT_PRIVATE_KEY")  # Expects PEM format
            if not private_key_pem:
                raise ValueError("JWT_PRIVATE_KEY not found in environment. RSA key is required for RS256.")

            # Example: Load from environment variable (PEM format)
            private_key = private_key_pem.encode('utf-8')

            # Example: Load from AWS KMS (replace with your KMS ARN and region)
            # private_key = get_private_key_from_aws_kms("arn:aws:kms:us-east-1:123456789012:key/your-key-id", "us-east-1")

            # Example: Load from HashiCorp Vault (replace with your Vault address and secret path)
            # private_key = get_private_key_from_vault("http://localhost:8200", "secret/data/jwt-key")

            return private_key

        except Exception as e:
            logging.error(f"Failed to load RSA private key: {e}")
            raise  # Re-raise to prevent application startup

    elif algorithm == 'HS256':
        # Load HMAC secret key from secure storage (Vault, etc.)
        try:
            secret_key = os.environ.get("JWT_SECRET_KEY")
            if not secret_key:
                raise ValueError("JWT_SECRET_KEY not found in environment. Secret key is required for HS256.")

            # Example: Load from HashiCorp Vault (replace with your Vault address and secret path)
            # secret_key = get_secret_from_vault("http://localhost:8200", "secret/data/jwt-secret")

            return secret_key.encode('utf-8')  # Ensure it's bytes
        except Exception as e:
            logging.error(f"Failed to load HMAC secret key: {e}")
            raise  # Re-raise to prevent application startup
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

# --- Example KMS Integration (AWS KMS) ---
# Requires boto3 library: pip install boto3
# import boto3
# def get_private_key_from_aws_kms(key_id, region_name):
#     """Retrieves the private key from AWS KMS."""
#     kms_client = boto3.client('kms', region_name=region_name)
#     response = kms_client.get_public_key(KeyId=key_id)
#     public_key_pem = response['PublicKey'].decode('utf-8') # This is the public key, not the private key.  KMS does not directly expose the private key.
#     # KMS is used for signing, not for directly retrieving the private key.  You would use KMS to sign the JWT.
#     # This example is incomplete and requires further implementation to use KMS for signing.
#     raise NotImplementedError("AWS KMS integration requires further implementation for signing.")

# --- Example Vault Integration (HashiCorp Vault) ---
# Requires hvac library: pip install hvac
# import hvac
# def get_secret_from_vault(vault_address, secret_path):
#     """Retrieves a secret from HashiCorp Vault."""
#     client = hvac.Client(url=vault_address)
#     # Ensure Vault is unsealed and you have a valid token
#     # client.token = os.environ.get("VAULT_TOKEN") # Or use a more secure authentication method
#     try:
#         response = client.secrets.kv.v2.read_secret(path=secret_path)
#         return response['data']['data']['value']  # Adjust based on your Vault secret structure
#     except Exception as e:
#         logging.error(f"Failed to retrieve secret from Vault: {e}")
#         raise

# def get_private_key_from_vault(vault_address, secret_path):
#     """Retrieves a private key from HashiCorp Vault."""
#     client = hvac.Client(url=vault_address)
#     # Ensure Vault is unsealed and you have a valid token
#     # client.token = os.environ.get("VAULT_TOKEN") # Or use a more secure authentication method
#     try:
#         response = client.secrets.kv.v2.read_secret(path=secret_path)
#         private_key_pem = response['data']['data']['private_key']  # Adjust based on your Vault secret structure
#         return private_key_pem.encode('utf-8')
#     except Exception as e:
#         logging.error(f"Failed to retrieve private key from Vault: {e}")
#         raise

def generate_jwt_token(payload, algorithm=ALGORITHM, expiration_time=TOKEN_EXPIRATION):
    """Generates a JWT token with the given payload."""
    payload['exp'] = int((timedelta(minutes=TOKEN_EXPIRATION_TIME) + datetime.utcnow()).timestamp())
    payload['nonce'] = secrets.token_hex(16)

    key = get_jwt_key(algorithm)

    if algorithm == 'RS256':
        token = jwt.encode(payload, key, algorithm=algorithm)
    elif algorithm == 'HS256':
        token = jwt.encode(payload, key, algorithm=algorithm)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return token

def verify_jwt_token(jwt_token, algorithm=ALGORITHM, nonce_store=None):
    """Verifies the JWT token and returns the payload if valid."""
    try:
        key = get_jwt_key(algorithm)

        if algorithm == 'RS256':
            payload = jwt.decode(jwt_token, key, algorithms=[algorithm])
        elif algorithm == 'HS256':
            payload = jwt.decode(jwt_token, key, algorithms=[algorithm])
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        # Nonce Validation
        if 'nonce' in payload:
            nonce = payload['nonce']
            if nonce_store and nonce_store.is_nonce_used(nonce):
                logging.warning(f"Replay attack detected: Nonce already used. User ID: {payload.get('user_id', 'N/A')}, Username: {payload.get('username', 'N/A')}")
                return None  # Or raise an exception
            if nonce_store:
                nonce_store.store_nonce(nonce)

        return payload
    except jwt.ExpiredSignatureError:
        logging.error("JWT Verification Error: Token has expired.")
        return None
    except jwt.InvalidSignatureError:
        logging.error("JWT Verification Error: Invalid signature.")
        return None
    except jwt.InvalidTokenError as e:
        logging.error(f"JWT Verification Error: Invalid token: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error during JWT verification: {e}")
        return None

def hash_password(password, salt=None):
    """Hashes a password using PBKDF2-HMAC."""
    if salt is None:
        salt = os.urandom(16)
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return hashed_password, salt

def verify_password(password, hashed_password, salt):
    """Verifies a password against a stored hash and salt."""
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return new_hash == hashed_password

def authorize(user_role, required_permission, roles=ROLES):
    """Checks if a user has the required permission."""
    if user_role in roles:
        permissions = roles[user_role]["permissions"]
        return required_permission in permissions
    else:
        return False

# --- Nonce Store (In-Memory - Replace with Persistent Store) ---
class InMemoryNonceStore:
    def __init__(self):
        self.nonces = set()

    def store_nonce(self, nonce):
        self.nonces.add(nonce)

    def is_nonce_used(self, nonce):
        return nonce in self.nonces

# --- Example Usage ---
if __name__ == '__main__':
    from datetime import datetime

    # 1. Password Hashing Example
    password = "my_secret_password"
    hashed_password, salt = hash_password(password)
    print(f"Hashed password: {hashed_password.hex()}")
    print(f"Salt: {salt.hex()}")

    is_valid = verify_password(password, hashed_password, salt)
    print(f"Password verification: {is_valid}")

    # 2. JWT Token Generation and Verification Example
    payload = {
        'user_id': 123,
        'username': 'testuser',
        'role': 'user'
    }

    jwt_algorithm = os.environ.get("JWT_ALGORITHM", "RS256")  # Default to RS256

    try:
        token = generate_jwt_token(payload, algorithm=jwt_algorithm)
        print(f"Generated JWT Token: {token}")

        # Initialize Nonce Store
        nonce_store = InMemoryNonceStore()

        verified_payload = verify_jwt_token(token, algorithm=jwt_algorithm, nonce_store=nonce_store)

        if verified_payload:
            print(f"Verified Payload: {verified_payload}")
        else:
            print("Token verification failed.")

        # Simulate a replay attack (using the same token again)
        verified_payload_replay = verify_jwt_token(token, algorithm=jwt_algorithm, nonce_store=nonce_store)
        if verified_payload_replay:
            print("Replay attack detected (but not prevented in this example)!")
        else:
            print("Replay attack prevented!")

    except ValueError as e:
        print(f"Error: {e}")  # Handle key loading errors

    # 3. Authorization Example
    user_role = verified_payload['role'] if verified_payload else 'guest'
    required_permission = "read"

    if authorize(user_role, required_permission):
        print(f"User with role '{user_role}' is authorized to '{required_permission}'.")
    else:
        print(f"User with role '{user_role}' is NOT authorized to '{required_permission}'.")

