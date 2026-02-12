import pickle
import hmac
import hashlib
import os
import time
import logging
import structlog
from typing import Dict, Any

# --- Logging Configuration ---
# Configure structlog for structured logging with JSON output
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# --- Secure Token Handling ---

# 1. Restricted Unpickler
# Define allowed classes for deserialization.  This is a crucial security measure to prevent arbitrary code execution.
# Mitigates CWE-502 (Deserialization of Untrusted Data).
ALLOWED_CLASSES: Dict[str, Any] = {
    "__main__": ["User", "Token"],  # Example: Allow User and Token classes defined in this file
    "datetime": ["datetime", "timedelta"], # Allow datetime objects
}


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # Only allow classes from the ALLOWED_CLASSES list.  This mitigates CWE-502 (Deserialization of Untrusted Data).
        if module in ALLOWED_CLASSES and name in ALLOWED_CLASSES[module]:
            return super().find_class(module, name)
        else:
            logger.warning("Attempt to unpickle forbidden class", module=module, name=name)  # Log the attempt
            raise pickle.UnpicklingError(f"Forbidden to unpickle: {module}.{name}")


def loads(s: bytes) -> Any:
    """Securely deserialize a pickled object."""
    return RestrictedUnpickler(io.BytesIO(s)).load()

# 2. HMAC for Integrity
# Use HMAC to ensure the integrity of the pickled data.  This prevents tampering with the serialized object.
# Mitigates CWE-352 (Cross-Site Request Forgery) and CWE-829 (Inclusion of Functionality From Untrusted Control Sphere)
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    logger.error("SECRET_KEY environment variable not set.  This is a critical security vulnerability.")
    raise ValueError("SECRET_KEY environment variable not set")

def create_token(data: Any) -> bytes:
    """Create a secure token by pickling, signing with HMAC, and encoding."""
    pickled_data = pickle.dumps(data)
    hmac_digest = hmac.new(SECRET_KEY.encode('utf-8'), pickled_data, hashlib.sha256).digest()
    return hmac_digest + pickled_data


def verify_token(token: bytes) -> Any:
    """Verify the token's integrity and deserialize the data."""
    hmac_digest = token[:hashlib.sha256().digest_size]
    pickled_data = token[hashlib.sha256().digest_size:]

    # Constant-time comparison to prevent timing attacks. Mitigates CWE-208 (Information Exposure Through Timing Discrepancy)
    try:
        hmac.compare_digest(hmac_digest, hmac.new(SECRET_KEY.encode('utf-8'), pickled_data, hashlib.sha256).digest())
    except Exception as e:
        logger.warning("Token verification failed", error=str(e))
        return None

    try:
        data = loads(pickled_data)
        return data
    except Exception as e:
        logger.error("Failed to deserialize token data", error=str(e))
        return None

# 3. Example Usage
class User:
    def __init__(self, username, user_id):
        self.username = username
        self.user_id = user_id

    def __repr__(self):
        return f"User(username='{self.username}', user_id={self.user_id})"

class Token:
    def __init__(self, token_id, user_id, expiration_time):
        self.token_id = token_id
        self.user_id = user_id
        self.expiration_time = expiration_time

    def __repr__(self):
        return f"Token(token_id='{self.token_id}', user_id={self.user_id}, expiration_time={self.expiration_time})"

if __name__ == "__main__":
    import io
    from datetime import datetime, timedelta

    # Example User and Token
    user = User("testuser", 123)
    expiration = datetime.utcnow() + timedelta(hours=1)
    token_data = Token("abc123xyz", user.user_id, expiration)

    # Create a secure token
    token = create_token(token_data)

    # Verify the token
    verified_token = verify_token(token)

    if verified_token:
        logger.info("Token verified successfully", token_data=str(verified_token))
        print(f"Verified Token Data: {verified_token}")
    else:
        logger.error("Token verification failed")
        print("Token verification failed.")

    # Tampered token example
    tampered_token = token[:-10] + b"AAAAAAAABB"  # Modify the token
    tampered_verified_token = verify_token(tampered_token)

    if tampered_verified_token:
        logger.info("Tampered token verified (this should not happen!)", token_data=str(tampered_verified_token))
        print(f"Tampered Token Data: {tampered_verified_token}")
    else:
        logger.warning("Tampered token verification failed (as expected)")
        print("Tampered token verification failed (as expected).")

    # Example of trying to unpickle a forbidden class
    class ForbiddenClass:
        def __init__(self, data):
            self.data = data

    try:
        forbidden_data = ForbiddenClass("secret")
        forbidden_token = create_token(forbidden_data)
        verify_token(forbidden_token)
    except pickle.UnpicklingError as e:
        logger.error("UnpicklingError occurred as expected", error=str(e))
        print(f"UnpicklingError: {e}")

# --- Important Security Considerations ---

# *   **Secret Key Management:** The `SECRET_KEY` must be securely generated (e.g., using `secrets.token_bytes(32)`) and stored (e.g., using environment variables, HashiCorp Vault, AWS Secrets Manager). Implement a key rotation policy.
# *   **`ALLOWED_CLASSES` Audit:**  Thoroughly audit the `ALLOWED_CLASSES` to prevent gadget chains and unintended consequences.  Be as specific as possible.
# *   **Logging:** Implement thorough and consistent redaction. Sanitize user-supplied data before logging it. Securely store and manage logs. Redact sensitive information (e.g., tokens, passwords, PII such as credit card numbers, social security numbers, and personally identifiable health information) from logs.
# *   **Rate Limiting:** Implement robust rate limiting to prevent abuse.  Use a more sophisticated mechanism (e.g., Redis, a dedicated rate-limiting library).  See example below.
# *   **Token Expiration and Revocation:** Implement proper token expiration and revocation mechanisms. Store token metadata (e.g., expiration time, user ID) in a database or cache. Check the token's validity against this metadata on every request. Provide a way to revoke tokens (e.g., by invalidating them in the database).
# *   **Input Validation:** Implement thorough input validation to ensure that user-supplied data is valid and safe to process. Use parameterized queries to prevent SQL injection. Avoid executing arbitrary commands based on user input.
# *   **JWT Considerations:** Consider using JWT (JSON Web Tokens) as an alternative to pickled tokens. However, JWTs don't automatically guarantee security. Always verify the JWT signature using a strong algorithm (e.g., RS256 or ES256). Never allow the `alg` header to be modified. Protect the secret key used to sign JWTs. Store JWTs securely (e.g., using HTTP-only cookies). Use short-lived tokens and implement refresh token mechanisms.  Popular Python JWT libraries include `PyJWT` and `Authlib`.
# *   **Defense in Depth:** Implement multiple layers of security controls. For example, in addition to `ALLOWED_CLASSES`, consider using input validation, output encoding, and other security measures.
# *   **CWE/OWASP Awareness:** Conduct a thorough security assessment of the code, using CWE/OWASP as a guide. Identify and address all relevant vulnerabilities.
# *   **Regular Security Audits:** Conduct regular security audits, penetration testing, and code reviews to identify and address potential vulnerabilities.

# Example (very basic) rate limiting for logging
import time

log_count = 0
log_limit = 100  # Limit to 100 log messages per minute (adjust as needed)
last_log_time = time.time()

def log_with_rate_limit(level, message, **kwargs):
    global log_count, last_log_time
    now = time.time()
    if now - last_log_time > 60:  # Reset counter every minute
        log_count = 0
        last_log_time = now

    if log_count < log_limit:
        logger.log(level, message, **kwargs)
        log_count += 1
    else:
        # Optionally, log that the rate limit was exceeded (but do so sparingly!)
        pass # logger.warning("Log rate limit exceeded")

# Example usage:
log_with_rate_limit(logging.WARNING, "Potential security issue", user_id=123)

