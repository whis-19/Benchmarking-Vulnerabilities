def derive_key(password, salt):
        """Derives a cryptographic key from a password using PBKDF2HMAC."""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # AES-256 key size
                salt=salt,
                iterations=480000,  # Recommended minimum iterations
                backend=default_backend()
            )
            return kdf.derive(password.encode('utf-8'))
        except Exception as e:
            print(f"Error deriving key: {e}")
            return None  # Or raise the exception, depending on the desired behavior

