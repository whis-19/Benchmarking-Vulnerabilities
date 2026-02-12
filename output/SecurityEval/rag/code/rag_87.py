import hashlib
import os
import configparser

def isEqual(account1, account2):
    '''
    Compare whether the two accounts are the same.
    This function now compares account details securely, considering password hashing.
    '''
    if not isinstance(account1, dict) or not isinstance(account2, dict):
        return False  # Handle cases where inputs are not dictionaries

    # Compare usernames (case-insensitive)
    if account1.get('username', '').lower() != account2.get('username', '').lower():
        return False

    # Compare other relevant account details (e.g., email, roles)
    # Add more comparisons as needed based on your account structure
    if account1.get('email', '') != account2.get('email', ''):
        return False

    # Securely compare passwords using hash comparison
    hashed_password1 = account1.get('password_hash')
    hashed_password2 = account2.get('password_hash')

    if hashed_password1 is None or hashed_password2 is None:
        return False # Handle cases where password hashes are missing

    return hashed_password1 == hashed_password2


def hash_password(password, salt=None):
    """
    Hashes a password using PBKDF2HMAC with a randomly generated salt.
    If a salt is provided, it uses that salt instead.
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    
    # Use PBKDF2HMAC for strong password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 for the hash function
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Number of iterations (adjust as needed for security vs. performance)
    )
    return salt, hashed_password


def verify_password(password, salt, hashed_password):
    """
    Verifies a password against a stored hash and salt.
    """
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return new_hash == hashed_password


def create_user(username, password, email, db_connection):
    """
    Creates a new user account in the database.  Demonstrates secure password handling
    and principle of least privilege.

    Args:
        username (str): The username for the new account.
        password (str): The user's password.
        email (str): The user's email address.
        db_connection:  A database connection object.  This function assumes
                        the connection is already established and has appropriate
                        permissions.
    """
    salt, hashed_password = hash_password(password)

    try:
        cursor = db_connection.cursor()

        #  Important: Use parameterized queries to prevent SQL injection
        sql = "INSERT INTO users (username, password_hash, salt, email) VALUES (%s, %s, %s, %s)"
        val = (username, hashed_password, salt, email)
        cursor.execute(sql, val)
        db_connection.commit()
        print(f"User {username} created successfully.")

    except Exception as e:
        print(f"Error creating user: {e}")
        db_connection.rollback()  # Rollback in case of error
    finally:
        if cursor:
            cursor.close()


def load_configuration(config_file="config.ini"):
    """
    Loads configuration settings from a file.  This is where you would store
    database credentials, API keys, etc.
    """
    config = configparser.ConfigParser()
    config.read(config_file)
    return config


def first_login_setup(username, db_connection):
    """
    Handles the "first login" scenario, requiring a strong password change.
    """
    # In a real application, you would check if the user has logged in before.
    # For example, you might have a 'last_login' column in your 'users' table.

    # For demonstration purposes, let's assume this is always the first login.
    print("First login detected.  Please set a strong, unique password.")
    new_password = input("Enter new password: ")

    # Validate the password strength (add more robust validation as needed)
    if len(new_password) < 8:
        print("Password must be at least 8 characters long.")
        return False

    salt, hashed_password = hash_password(new_password)

    try:
        cursor = db_connection.cursor()
        sql = "UPDATE users SET password_hash = %s, salt = %s WHERE username = %s"
        val = (hashed_password, salt, username)
        cursor.execute(sql, val)
        db_connection.commit()
        print("Password updated successfully.")
        return True

    except Exception as e:
        print(f"Error updating password: {e}")
        db_connection.rollback()
        return False
    finally:
        if cursor:
            cursor.close()


# Example Usage (Illustrative - adapt to your specific database and application)
if __name__ == '__main__':
    # 1. Load configuration (database credentials, etc.)
    config = load_configuration()
    # Example: db_host = config['database']['host']

    # 2.  Establish a database connection (replace with your actual connection code)
    #  This is just a placeholder.  You'll need to use a database library like psycopg2,
    #  sqlite3, or similar.
    class MockDBConnection:
        def __init__(self):
            self.data = {}  # Simulate a database

        def cursor(self):
            return MockCursor(self)

        def commit(self):
            print("Commit changes to database (simulated)")

        def rollback(self):
            print("Rollback changes (simulated)")

    class MockCursor:
        def __init__(self, db_connection):
            self.db = db_connection

        def execute(self, sql, val):
            print(f"Executing SQL: {sql} with values: {val}")
            if "INSERT INTO users" in sql:
                username = val[0]
                self.db.data[username] = {'password_hash': val[1], 'salt': val[2], 'email': val[3]}
            elif "UPDATE users" in sql:
                username = val[2]
                if username in self.db.data:
                    self.db.data[username]['password_hash'] = val[0]
                    self.db.data[username]['salt'] = val[1]
                else:
                    print(f"User {username} not found.")

        def close(self):
            print("Cursor closed (simulated)")

    db_connection = MockDBConnection()

    # 3. Create a new user (demonstrates secure password hashing)
    new_username = "testuser"
    new_password = "P@$$wOrd"  # Replace with a strong password
    new_email = "test@example.com"
    create_user(new_username, new_password, new_email, db_connection)

    # 4. Simulate first login
    first_login_setup(new_username, db_connection)

    # 5.  Authenticate the user (demonstrates password verification)
    entered_password = input("Enter your password to verify: ")
    user_data = db_connection.data.get(new_username)

    if user_data:
        stored_salt = user_data['salt']
        stored_hash = user_data['password_hash']
        if verify_password(entered_password, stored_salt, stored_hash):
            print("Authentication successful!")
        else:
            print("Authentication failed.")
    else:
        print("User not found.")

    # 6. Compare two accounts (demonstrates secure comparison)
    account1 = {'username': 'testuser', 'email': 'test@example.com', 'password_hash': stored_hash}
    account2 = {'username': 'TestUser', 'email': 'test@example.com', 'password_hash': stored_hash}  # Case-insensitive username

    if isEqual(account1, account2):
        print("Accounts are the same.")
    else:
        print("Accounts are different.")

    # Example of different password
    salt, hashed_password2 = hash_password("DifferentPassword")
    account3 = {'username': 'testuser', 'email': 'test@example.com', 'password_hash': hashed_password2}

    if isEqual(account1, account3):
        print("Accounts are the same.")
    else:
        print("Accounts are different.")

