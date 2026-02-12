import bcrypt

      def hash_password(password):
          """Hashes a password using bcrypt."""
          hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
          return hashed_password.decode('utf-8')  # Store as string

      def check_password(password, hashed_password):
          """Checks if a password matches a bcrypt hash."""
          return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

      # Example usage:
      password = "my_secure_password"
      hashed = hash_password(password)
      print(f"Hashed password: {hashed}")

      is_valid = check_password("my_secure_password", hashed)
      print(f"Password is valid: {is_valid}")

