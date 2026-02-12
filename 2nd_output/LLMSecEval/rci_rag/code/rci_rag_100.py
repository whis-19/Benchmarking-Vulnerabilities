def hash_password(password):
        """Hashes the password using bcrypt."""
        salt = bcrypt.gensalt(rounds=12)  # Increase the number of rounds (default is often 12)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')  # Store as string

