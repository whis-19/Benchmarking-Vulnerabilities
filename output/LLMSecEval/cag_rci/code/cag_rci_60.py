import bcrypt

        # When creating a new user:
        password = "user's password"
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        # Store hashed_password in the database

        # When verifying a password:
        stored_hashed_password = user['password'] # Retrieve from database
        if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
            print("Password matches")
        else:
            print("Password does not match")

