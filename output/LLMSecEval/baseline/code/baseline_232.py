import bcrypt

      def hash_password(password):
          """Hashes the password using bcrypt."""
          hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
          return hashed_password.decode('utf-8')  # Store as string

      def verify_password(password, stored_hash):
          """Verifies a password against a bcrypt hash."""
          return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

      # In register_user:
      password_hash = hash_password(password)
      salt = "" # No need for separate salt with bcrypt

      # In verify_password:
      if verify_password(password, stored_password_hash):
          # Password is correct

