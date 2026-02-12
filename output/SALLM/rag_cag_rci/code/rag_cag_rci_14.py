import hashlib

    def derive_hmac_key(secret_key: str) -> bytes:
        """Derives a separate key for HMAC."""
        hmac_key = hashlib.sha256((secret_key + "hmac_salt").encode()).digest()  # Use a fixed salt
        return hmac_key

    HMAC_KEY = derive_hmac_key(SECRET_KEY)

