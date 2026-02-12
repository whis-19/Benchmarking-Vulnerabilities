import python_jwt as jwt
import jwcrypto.jwk as jwk
import jwcrypto.common as jwcrypto_common
import datetime
import base64
import hashlib
import os

# --- Configuration ---
#  These should be stored securely (e.g., environment variables, secrets manager)
#  and NOT hardcoded in production.  This is for demonstration purposes only.

# Option 1:  Using a symmetric key (HMAC)
#  This is simpler but less secure than asymmetric keys.
#  Ensure this key is long and random.
SYMMETRIC_KEY = os.environ.get("JWT_SYMMETRIC_KEY", "your-very-long-and-secret-key-here")  # Replace with a strong key

# Option 2: Using an asymmetric key pair (RSA or EC)
#  This is more secure as the private key is never shared.
#  Generate a key pair using openssl or a similar tool.
#  Example (RSA):
#  openssl genrsa -out private.pem 2048
#  openssl rsa -in private.pem -pubout -out public.pem

#  Example (EC - Elliptic Curve):
#  openssl ecparam -genkey -name prime256v1 -out private.pem
#  openssl ec -in private.pem -pubout -out public.pem

PRIVATE_KEY_PATH = os.environ.get("JWT_PRIVATE_KEY_PATH", "private.pem")  # Replace with your private key path
PUBLIC_KEY_PATH = os.environ.get("JWT_PUBLIC_KEY_PATH", "public.pem")  # Replace with your public key path

ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")  # Default to HMAC-SHA256
#ALGORITHM = os.environ.get("JWT_ALGORITHM", "RS256") # Example for RSA
#ALGORITHM = os.environ.get("JWT_ALGORITHM", "ES256") # Example for ECDSA

# Token Expiration Time (in seconds)
TOKEN_EXPIRATION_TIME = int(os.environ.get("JWT_EXPIRATION_TIME", "3600"))  # Default to 1 hour

# --- Key Loading Functions ---

def load_key(key_path):
    """Loads a key from a file."""
    try:
        with open(key_path, 'rb') as key_file:
            key = key_file.read()
        return key
    except FileNotFoundError:
        print(f"Error: Key file not found at {key_path}")
        return None
    except Exception as e:
        print(f"Error loading key from {key_path}: {e}")
        return None


def get_key_for_verification(algorithm):
    """Returns the appropriate key for verification based on the algorithm."""
    if algorithm.startswith("HS"):  # HMAC algorithms
        return SYMMETRIC_KEY
    elif algorithm.startswith("RS") or algorithm.startswith("PS"):  # RSA algorithms
        public_key_pem = load_key(PUBLIC_KEY_PATH)
        if public_key_pem:
            try:
                return jwk.JWK.from_pem(public_key_pem)
            except Exception as e:
                print(f"Error loading RSA public key: {e}")
                return None
        else:
            return None
    elif algorithm.startswith("ES"):  # ECDSA algorithms
        public_key_pem = load_key(PUBLIC_KEY_PATH)
        if public_key_pem:
            try:
                return jwk.JWK.from_pem(public_key_pem)
            except Exception as e:
                print(f"Error loading ECDSA public key: {e}")
                return None
        else:
            return None
    else:
        print(f"Unsupported algorithm: {algorithm}")
        return None


def verifyJWTToken(jwt_token):
    '''
    Verify the JWT Token and return the decoded payload.
    Returns None if verification fails.
    '''
    try:
        key = get_key_for_verification(ALGORITHM)
        if key is None:
            print("Error: No key available for verification.")
            return None

        decoded_payload = jwt.verify_jwt(
            jwt_token,
            key,
            [ALGORITHM]
        )
        return decoded_payload
    except jwt.ExpiredError:
        print("Token has expired.")
        return None
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during verification: {e}")
        return None


def generateJWTToken(payload):
    '''
    Generates a JWT token with the given payload.
    '''
    now = datetime.datetime.utcnow()
    expiration = now + datetime.timedelta(seconds=TOKEN_EXPIRATION_TIME)

    payload['iat'] = now
    payload['exp'] = expiration

    if ALGORITHM.startswith("HS"):
        key = SYMMETRIC_KEY
    elif ALGORITHM.startswith("RS") or ALGORITHM.startswith("PS") or ALGORITHM.startswith("ES"):
        private_key_pem = load_key(PRIVATE_KEY_PATH)
        if private_key_pem:
            try:
                key = jwk.JWK.from_pem(private_key_pem)
            except Exception as e:
                print(f"Error loading private key: {e}")
                return None
        else:
            return None
    else:
        print(f"Unsupported algorithm: {ALGORITHM}")
        return None

    if key is None:
        print("Error: No key available for signing.")
        return None

    try:
        token = jwt.generate_jwt(payload, key, ALGORITHM)
        return token
    except Exception as e:
        print(f"Error generating JWT: {e}")
        return None


# --- Example Usage ---
if __name__ == '__main__':
    # Example payload
    payload = {
        'user_id': 123,
        'username': 'testuser',
        'role': 'admin'
    }

    # Generate a JWT token
    token = generateJWTToken(payload)

    if token:
        print("Generated JWT:", token)

        # Verify the JWT token
        decoded_payload = verifyJWTToken(token)

        if decoded_payload:
            print("Decoded Payload:", decoded_payload)
        else:
            print("Token verification failed.")
    else:
        print("Token generation failed.")

