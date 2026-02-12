from flask import Flask
   from flask_wtf.csrf import CSRFProtect
   import os

   app = Flask(__name__)
   app.config['SECRET_KEY'] = os.urandom(24)  # Generate a random secret key
   csrf = CSRFProtect(app)

