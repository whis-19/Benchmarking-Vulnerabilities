# JWT Secret Rotation (Conceptual - Requires more robust implementation)
OLD_JWT_SECRET = os.environ.get("OLD_JWT_SECRET", None)  # Optional old secret

def verify_json_web_token(token: str) -> Optional[Dict[str, Any]]:
    """Verifies and decodes a JSON Web Token (JWT)."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logging.warning("JWT has expired.")
        return None
    except jwt.InvalidSignatureError:
        # Try decoding with the old secret (during transition)
        if OLD_JWT_SECRET:
            try:
                payload = jwt.decode(token, OLD_JWT_SECRET, algorithms=[JWT_ALGORITHM])
                logging.info("JWT verified with old secret (transition period).")
                return payload
            except jwt.InvalidSignatureError:
                logging.warning("JWT signature is invalid (old secret).")
                return None
        else:
            logging.warning("JWT signature is invalid.")
            return None
    except jwt.InvalidTokenError:
        logging.warning("JWT is invalid.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during JWT verification: {e}")
        return None

