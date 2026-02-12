from flask_bcrypt import Bcrypt
   app = Flask(__name__)
   bcrypt = Bcrypt(app)

   # ...

   hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
   # Store hashed_password in the database

   # To check the password:
   if bcrypt.check_password_hash(stored_hash, password):
       # Password matches

