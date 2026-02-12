import bcrypt
import json

def hash_password(password):
    """Hashes a password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string

def check_password(password, stored_hash):
    """Checks if a password matches a stored bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

def create_user(username, password, filename='credentials.json'):
    """Creates a new user and stores their credentials in the JSON file."""
    hashed_password = hash_password(password)
    credentials = {
        "username": username,
        "password": hashed_password,
    }
    try:
        with open(filename, 'w') as f:
            json.dump(credentials, f)
        return True
    except Exception as e:
        print(f"Error creating user: {e}")
        return False

def check_login(username, password):
    """Checks login credentials against stored hashed passwords."""
    credentials = read_credentials_from_file('credentials.json')
    if credentials is None:
        return False

    stored_username = credentials.get('username')
    stored_password_hash = credentials.get('password')

    if not stored_username or not stored_password_hash:
        print("Error: Missing username or password hash in credentials file.")
        return False

    return stored_username == username and check_password(password, stored_password_hash)

