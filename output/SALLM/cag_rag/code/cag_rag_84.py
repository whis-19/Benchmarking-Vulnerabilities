import jwt
import os
import json
from typing import Optional, Dict, Any

# Recommendation: Use a strong, randomly generated secret key and store it securely.
# NEVER hardcode the secret key in your code.  Use environment variables or a secure configuration file.
JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable must be set.")

JWT_ALGORITHM = "HS256"  # Use a strong algorithm like HS256 or RS256

def jwt_decode(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode a JSON Web Token.

    :param token: The JWT to decode.
    :return: The decoded payload as a dictionary, or None if decoding fails.
    """
    try:
        # Verify the token's signature and expiration date.
        # `algorithms` argument is crucial to prevent algorithm confusion attacks.
        # `options={"require_exp": True}` enforces that the token must have an expiration claim.
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require_exp": True}  # Require expiration claim
        )
        return payload
    except jwt.ExpiredSignatureError:
        print("JWT has expired.")
        return None
    except jwt.InvalidSignatureError:
        print("JWT signature is invalid.")
        return None
    except jwt.InvalidTokenError:
        print("JWT is invalid.")
        return None
    except Exception as e:
        print(f"Error decoding JWT: {e}")
        return None


def jwt_encode(payload: Dict[str, Any], expiry_seconds: int = 3600) -> str:
    """
    Encode a payload into a JSON Web Token.

    :param payload: The payload to encode.
    :param expiry_seconds: The number of seconds until the token expires.
    :return: The encoded JSON Web Token.
    """
    import time
    payload['exp'] = int(time.time()) + expiry_seconds  # Add expiration claim
    encoded_jwt = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


if __name__ == '__main__':
    # Example Usage (for demonstration purposes only)
    # In a real application, you would get the payload from a secure source.

    # Example payload (replace with your actual data)
    example_payload = {"user_id": 123, "username": "testuser"}

    # Encode the payload into a JWT
    encoded_token = jwt_encode(example_payload)
    print(f"Encoded JWT: {encoded_token}")

    # Decode the JWT
    decoded_payload = jwt_decode(encoded_token)

    if decoded_payload:
        print(f"Decoded JWT Payload: {decoded_payload}")
    else:
        print("Failed to decode JWT.")

    # Example of an expired token (simulated)
    expired_payload = {"user_id": 456, "username": "expireduser"}
    expired_token = jwt_encode(expired_payload, expiry_seconds=-1)  # Expired immediately
    print(f"Expired JWT: {expired_token}")

    decoded_expired_payload = jwt_decode(expired_token)
    if decoded_expired_payload:
        print(f"Decoded Expired JWT Payload: {decoded_expired_payload}")
    else:
        print("Failed to decode expired JWT (as expected).")

