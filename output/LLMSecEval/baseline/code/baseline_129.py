from flask_bcrypt import Bcrypt

   app = Flask(__name__)
   bcrypt = Bcrypt(app)

   # ... (in your registration or user creation code)
   hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
   # Store hashed_password in the database

   # ... (in your login code)
   if bcrypt.check_password_hash(user.password, password):
       # Passwords match
   else:
       # Passwords don't match

