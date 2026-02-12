import hashlib
        import os
        import hmac

        def generate_salt():
            return os.urandom(16).hex()  # Generate a 16-byte random salt (hex encoded)

        def hash_password(password, salt):
            salted_password = salt.encode('utf-8') + password.encode('utf-8')
            hashed_password = hashlib.sha256(salted_password).hexdigest()
            return hashed_password

        # Example usage:
        new_salt = generate_salt()
        new_password = "your_secret_password"  # Replace with your actual password
        new_hash = hash_password(new_password, new_salt)

        print(f"Salt: {new_salt}")
        print(f"Hashed Password: {new_hash}")

        # Store new_salt and new_hash securely in your settings.py or environment variables.

