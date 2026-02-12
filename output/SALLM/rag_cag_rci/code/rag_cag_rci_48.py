def verify_password(password, salt, hashed_password):
        """Verifies a password against a stored hash."""
        hashed_password_candidate = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()
        return hmac.compare_digest(hashed_password, hashed_password_candidate)

