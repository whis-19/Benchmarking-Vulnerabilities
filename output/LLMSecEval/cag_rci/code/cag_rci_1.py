import secrets
   app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generate a strong, random key

