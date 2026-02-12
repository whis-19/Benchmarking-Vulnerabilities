import hashlib
        import secrets

        def hash_password(password):
            """Hashes the password using pbkdf2_hmac."""
            salt = secrets.token_hex(16)
            password_bytes = password.encode('utf-8')
            salt_bytes = salt.encode('utf-8')
            hashed_password = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 100000).hex()
            return f"{salt}${hashed_password}"  # Store salt and hash together

        admin_password = "your_admin_password"  # Replace with your desired password
        hashed_password = hash_password(admin_password)
        print(f"Hashed admin password: {hashed_password}")

