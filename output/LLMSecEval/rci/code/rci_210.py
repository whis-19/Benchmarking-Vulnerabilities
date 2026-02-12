def verify_password(stored_password, provided_password):
        """Verifies the provided password against the stored bcrypt hash."""
        return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))

