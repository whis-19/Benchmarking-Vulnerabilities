import bcrypt

      def hash_password(password):
          """Hashes the password using bcrypt."""
          password_bytes = password.encode('utf-8')
          hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
          return hashed_password.decode('utf-8')  # Store as string

      def create_user(username, password, db_path="users.db"):
          hashed_password = hash_password(password)
          # ... (rest of the database code, but you don't need to store a separate salt)
          cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", (username, hashed_password))
          # ...

