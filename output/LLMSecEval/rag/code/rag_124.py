from werkzeug.security import generate_password_hash, check_password_hash

   def create_user(username, password):
       hashed_password = generate_password_hash(password)
       # ... store username and hashed_password in the database

   def authenticate_user(username, password):
       # ... retrieve hashed_password from the database
       if check_password_hash(stored_hash, password):
           return True
       else:
           return False

