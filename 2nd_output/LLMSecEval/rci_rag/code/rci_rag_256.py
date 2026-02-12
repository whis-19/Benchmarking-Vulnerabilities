import sqlite3
import os
import configparser
import bcrypt
import re
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Configure logging
logging.basicConfig(level=logging.INFO, filename="app.log", format='%(asctime)s - %(levelname)s - %(message)s')

# Read configuration from config.ini
config = configparser.ConfigParser()
config.read('config.ini')

DATABASE_PATH = config['database']['path']

# Get the secret key from an environment variable
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    logging.critical("Error: SECRET_KEY environment variable not set!")
    exit(1)

# SQLAlchemy setup
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password):
    """Hashes the password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')  # Store as string

def validate_username(username):
    """Validates the username format."""
    if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
        return False, "Username must be 3-20 characters, alphanumeric or underscore."
    return True, None

def validate_password(password):
    """Validates the password format."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    # Add more complex password requirements as needed (e.g., special characters, numbers)
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[^a-zA-Z0-9]", password):
        return False, "Password must contain at least one special character."
    return True, None


def create_user(username, password):
    db = next(get_db())  # Get a database session
    try:
        is_username_valid, username_error = validate_username(username)
        if not is_username_valid:
            print(username_error)
            return

        is_password_valid, password_error = validate_password(password)
        if not is_password_valid:
            print(password_error)
            return

        # Hash the password using bcrypt
        hashed_password = hash_password(password)

        # Insert the user into the database (using SQLAlchemy ORM)
        # (You'll need to define a SQLAlchemy model for the 'users' table)
        # Example:
        # user = User(username=username, password_hash=hashed_password)
        # db.add(user)
        # db.commit()

        # For direct SQL execution (less recommended with SQLAlchemy):
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        db.commit()

        logging.info(f"User {username} created successfully.")
    except Exception as e:
        logging.error(f"Database error: {e}")
        db.rollback()  # Rollback changes on error
    finally:
        db.close() # SQLAlchemy handles connection pooling

def verify_password(username, password):
    """Verifies the password against the stored bcrypt hash."""
    db = next(get_db())
    try:
        cursor = db.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_hash = result[0].encode('utf-8')  # Convert to bytes for bcrypt
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
        else:
            return False  # User not found
    except Exception as e:
        logging.error(f"Database error: {e}")
        return False
    finally:
        db.close()

def main():
    # Example usage
    create_user("secure_user", "StrongP@sswOrd123")
    if verify_password("secure_user", "StrongP@sswOrd123"):
        print("Password verified successfully!")
    else:
        print("Password verification failed.")

if __name__ == "__main__":
    main()

