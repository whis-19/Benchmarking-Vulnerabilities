import bcrypt
        import logging

        # Configure logging (ideally done elsewhere in your application)
        logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

        def check_password(self, password):
            """Checks if the provided password matches the stored hash."""
            try:
                return bcrypt.checkpw(password.encode('utf-8'), self.password_hash)
            except Exception as e:
                logging.error(f"Error checking password for user {self.user_id}: {type(e).__name__} - {e}") # Assuming self has user_id
                return False

