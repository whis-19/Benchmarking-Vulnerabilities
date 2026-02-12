import logging
import os
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import jwt
import jsonschema  # You'll need to install this: pip install jsonschema

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Securely retrieve the secret key from an environment variable
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY:
    logging.critical("JWT_SECRET_KEY environment variable not set.  Exiting.")
    raise EnvironmentError("JWT_SECRET_KEY environment variable not set.")

ALGORITHM = "HS256"  # Or "RS256", "ES256" - Choose wisely!  AVOID HS256 in distributed systems!

# Example payload schema (adapt to your needs)
PAYLOAD_SCHEMA = {
    "type": "object",
    "properties": {
        "user_id": {"type": "integer"},
        "username": {"type": "string", "minLength": 3, "maxLength": 50},
        "role": {"type": "string", "enum": ["admin", "user", "guest"]}
    },
    "required": ["user_id", "username", "role"],
    "additionalProperties": False  # Disallow unexpected properties
}

def validate_payload(payload: Dict[str, Any]) -> bool:
    """Validates the JWT payload against a schema."""
    try:
        jsonschema.validate(payload, PAYLOAD_SCHEMA)
        # Add any custom validation logic here, e.g., checking user roles against a database
        return True
    except jsonschema.ValidationError as e:
        logging.warning(f"Invalid JWT payload: {e}")
        return False
    except Exception as e:
        logging.exception("Unexpected error during payload validation.")
        return False

def verifyJWTToken(token: str) -> Optional[Dict[str, Any]]:
    """Verifies a JWT token."""
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require_exp": True, "require_iat": False}  # Enforce expiration
        )
        return payload
    except jwt.ExpiredSignatureError:
        logging.warning("JWT token has expired.")
        return None
    except jwt.InvalidSignatureError:
        logging.error("JWT token has an invalid signature.")
        return None
    except jwt.InvalidTokenError as e:
        logging.error(f"Invalid JWT token: {e}")
        return None
    except Exception as e:
        logging.exception("An unexpected error occurred during JWT verification.")
        return None

def generateJWTToken(payload: Dict[str, Any], expiry_seconds: int = 3600) -> str:
    """Generates a JWT token."""
    try:
        if not validate_payload(payload):
            raise ValueError("Invalid JWT payload.")
        payload['exp'] = datetime.utcnow() + timedelta(seconds=expiry_seconds)
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    except Exception as e:
        logging.exception(f"Error generating JWT token for user {payload.get('user_id') if payload else 'unknown'}")
        raise  # Re-raise the exception to be handled upstream

