import python_jwt as jwt
import jwcrypto.jwk as jwk
import jwcrypto.common as jwcrypto_common
import datetime
import base64
import hashlib
import os

# --- Configuration ---
#  These should be stored securely (e.g., environment variables, secrets management)
#  and NOT hardcoded in production.  This is for demonstration purposes only.

# Option 1:  Using a symmetric key (HMAC)
#  This is simpler but less secure than asymmetric keys.
#  Ensure this key is VERY strong and kept secret.
#  A good key should be at least 32 bytes (256 bits) of random data.
#  Example:  `openssl rand -base64 32`
SYMMETRIC_KEY = os.environ.get("JWT_SYMMETRIC_KEY", None)  # Replace with a strong, secret key.  MUST be set.

# Option 2: Using an asymmetric key pair (RSA or EC)
#  This is more secure as the private key is never shared.
#  You'll need to generate a key pair.  For example, using OpenSSL:
#  `openssl genrsa -out private.pem 2048`
#  `openssl rsa -in private.pem -pubout -out public.pem`
#  Or for EC (Elliptic Curve):
#  `openssl ecparam -genkey -name prime256v1 -out private.pem`
#  `openssl ec -in private.pem -pubout -out public.pem`

#  Load the public key.  This is used for verification.
#  The private key is used for signing (not shown here, as this function only verifies).
PUBLIC_KEY_PEM = os.environ.get("JWT_PUBLIC_KEY_PEM", None)  # Replace with your public key PEM string
PRIVATE_KEY_PEM = os.environ.get("JWT_PRIVATE_KEY_PEM", None) # Replace with your private key PEM string (for signing elsewhere)

# Algorithm to use for signing/verifying.  Choose one that matches your key type.
#  HS256: HMAC with SHA-256 (symmetric key)
#  RS256: RSA with SHA-256 (asymmetric key)
#  ES256: ECDSA with SHA-256 (asymmetric key)
ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")  # Replace with your chosen algorithm

# Token expiration time (in seconds).  Set this to a reasonable value.
TOKEN_EXPIRATION_TIME = int(os.environ.get("JWT_EXPIRATION_TIME", 3600))  # 1 hour default

# --- End Configuration ---

ALLOWED_ALGORITHMS = ["HS256", "RS256", "ES256"]


def verifyJWTToken(jwt_token):
    '''
    Verify the JWT Token and return the decoded payload if valid.
    Raises exceptions if the token is invalid.
    '''
    try:
        if not isinstance(jwt_token, str):
            raise ValueError("JWT token must be a string.")

        if ALGORITHM not in ALLOWED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {ALGORITHM}")

        if ALGORITHM.startswith("HS"):  # Symmetric key (HMAC)
            if not SYMMETRIC_KEY:
                raise ValueError("JWT_SYMMETRIC_KEY must be set when using HS256.")
            key = SYMMETRIC_KEY.encode("utf-8")  # Ensure key is bytes
            decoded_payload = jwt.verify_jwt(
                jwt_token,
                key,
                [ALGORITHM]
            )
        elif ALGORITHM.startswith("RS") or ALGORITHM.startswith("ES"):  # Asymmetric key (RSA or EC)
            if not PUBLIC_KEY_PEM:
                raise ValueError("PUBLIC_KEY_PEM must be set when using an asymmetric algorithm.")

            # Load the public key from PEM format
            public_key = jwk.JWK.from_pem(PUBLIC_KEY_PEM.encode("utf-8"))

            decoded_payload = jwt.verify_jwt(
                jwt_token,
                public_key,
                [ALGORITHM]
            )
        else:
            raise ValueError(f"Unsupported algorithm: {ALGORITHM}")

        return decoded_payload

    except jwt.ExpiredTokenError:
        raise Exception("JWT token has expired.")
    except jwt.InvalidTokenError as e:
        raise Exception(f"Invalid JWT token: {e}")
    except ValueError as e:
        raise Exception(f"Configuration error: {e}")
    except Exception as e:
        raise Exception(f"Error verifying JWT token: {e}")


def generateJWTToken(payload):
    '''
    Generates a JWT token given a payload.  This is for demonstration and should
    be in a separate function/module.
    '''
    try:
        now = datetime.datetime.utcnow()
        # Set the expiration time of the token
        # The 'exp' claim is automatically verified by the library
        # The 'iat' claim is optional, but good practice
        expiry = now + datetime.timedelta(seconds=TOKEN_EXPIRATION_TIME)

        payload['exp'] = expiry
        payload['iat'] = now

        if ALGORITHM not in ALLOWED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {ALGORITHM}")

        if ALGORITHM.startswith("HS"):  # Symmetric key (HMAC)
            if not SYMMETRIC_KEY:
                raise ValueError("JWT_SYMMETRIC_KEY must be set when using HS256.")
            key = SYMMETRIC_KEY.encode("utf-8")  # Ensure key is bytes
            jwt_token = jwt.generate_jwt(payload, key, ALGORITHM)
        elif ALGORITHM.startswith("RS") or ALGORITHM.startswith("ES"):  # Asymmetric key (RSA or EC)
            if not PRIVATE_KEY_PEM:
                raise ValueError("PRIVATE_KEY_PEM must be set when using an asymmetric algorithm.")

            # Load the private key from PEM format
            private_key = jwk.JWK.from_pem(PRIVATE_KEY_PEM.encode("utf-8"))

            jwt_token = jwt.generate_jwt(payload, private_key, ALGORITHM)
        else:
            raise ValueError(f"Unsupported algorithm: {ALGORITHM}")

        return jwt_token

    except ValueError as e:
        raise Exception(f"Configuration error: {e}")
    except Exception as e:
        raise Exception(f"Error generating JWT token: {e}")


if __name__ == '__main__':
    # Example Usage (Demonstration Only - Replace with Secure Key Management)

    # Example payload
    payload = {
        'user_id': 123,
        'username': 'testuser',
        'role': 'admin'
    }

    try:
        # Generate a JWT token
        token = generateJWTToken(payload)
        print(f"Generated JWT Token: {token}")

        # Verify the JWT token
        decoded_payload = verifyJWTToken(token)
        print(f"Decoded Payload: {decoded_payload}")

    except Exception as e:
        print(f"An error occurred: {e}")

