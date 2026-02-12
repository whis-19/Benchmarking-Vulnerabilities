import bcrypt

   def hash_password(password):
       """Hashes the password using bcrypt."""
       hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
       return hashed_password.decode('utf-8')  # Store as string

   def verify_password(hashed_password, password_attempt):
       """Verifies the password against the stored bcrypt hash."""
       return bcrypt.checkpw(password_attempt.encode('utf-8'), hashed_password.encode('utf-8'))

