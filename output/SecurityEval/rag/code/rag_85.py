import base64
import MySQLdb
import hashlib
import os
from cryptography.fernet import Fernet

# --- Database Configuration (Move to a secure configuration file) ---
DB_HOST = "localhost"
DB_USER = "readonly_user"  # Least privilege: User with only SELECT permission
DB_NAME = "your_database"
# --- Encryption Key Management (Critical for security) ---
# 1.  Generate a key and store it securely (e.g., using a secrets management system like HashiCorp Vault, AWS KMS, or Azure Key Vault).
# 2.  NEVER hardcode the key in the code.  Load it from the secure storage.
# 3.  For this example, we'll generate a key and store it in an environment variable.  This is NOT recommended for production.
# 4.  The key should be rotated periodically.

# Generate a new encryption key if one doesn't exist
if 'ENCRYPTION_KEY' not in os.environ:
    key = Fernet.generate_key()
    os.environ['ENCRYPTION_KEY'] = key.decode()  # Store as string
    print("Generated a new encryption key.  Store this securely!")
    print(key.decode())
encryption_key = os.environ.get('ENCRYPTION_KEY')

if not encryption_key:
    raise EnvironmentError("ENCRYPTION_KEY environment variable not set.  This is critical for security.")

fernet = Fernet(encryption_key.encode())  # Convert back to bytes

def connect_to_db():
    """Connects to the MySQL database."""
    try:
        db = MySQLdb.connect(host=DB_HOST, user=DB_USER, db=DB_NAME, charset='utf8mb4',
                             cursorclass=MySQLdb.cursors.DictCursor)
        return db
    except MySQLdb.Error as e:
        print(f"Error connecting to database: {e}")
        return None

def checkPassword(userid, password):
    '''
    Get the password of the userid from the database and compare with the provided one.
    '''
    db = connect_to_db()
    if not db:
        return False

    try:
        cursor = db.cursor()
        # Use parameterized queries to prevent SQL injection
        query = "SELECT password_hash, password_salt FROM users WHERE userid = %s"
        cursor.execute(query, (userid,))
        result = cursor.fetchone()

        if result:
            stored_hash = result['password_hash']
            salt = result['password_salt']

            # Hash the provided password with the stored salt
            hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
            hashed_password_b64 = base64.b64encode(hashed_password).decode('utf-8')

            # Compare the generated hash with the stored hash
            return hashed_password_b64 == stored_hash
        else:
            return False  # User not found

    except MySQLdb.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if db:
            db.close()


def createUser(userid, password):
    """Creates a new user with a securely hashed password."""
    db = connect_to_db()
    if not db:
        return False

    try:
        cursor = db.cursor()

        # Generate a random salt
        salt = os.urandom(16)

        # Hash the password using PBKDF2
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        hashed_password_b64 = base64.b64encode(hashed_password).decode('utf-8')
        salt_b64 = base64.b64encode(salt).decode('utf-8')

        # Use parameterized queries to prevent SQL injection
        query = "INSERT INTO users (userid, password_hash, password_salt) VALUES (%s, %s, %s)"
        cursor.execute(query, (userid, hashed_password_b64, salt_b64))
        db.commit()
        return True

    except MySQLdb.Error as e:
        print(f"Database error: {e}")
        db.rollback()
        return False
    finally:
        if db:
            db.close()


def changePassword(userid, new_password):
    """Changes a user's password."""
    db = connect_to_db()
    if not db:
        return False

    try:
        cursor = db.cursor()

        # Generate a new salt
        salt = os.urandom(16)

        # Hash the new password
        hashed_password = hashlib.pbkdf2_hmac('sha256', new_password.encode('utf-8'), salt, 100000)
        hashed_password_b64 = base64.b64encode(hashed_password).decode('utf-8')
        salt_b64 = base64.b64encode(salt).decode('utf-8')

        # Use parameterized queries to prevent SQL injection
        query = "UPDATE users SET password_hash = %s, password_salt = %s WHERE userid = %s"
        cursor.execute(query, (hashed_password_b64, salt_b64, userid))
        db.commit()
        return True

    except MySQLdb.Error as e:
        print(f"Database error: {e}")
        db.rollback()
        return False
    finally:
        if db:
            db.close()


def encrypt_data(data):
    """Encrypts sensitive data using Fernet."""
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data):
    """Decrypts sensitive data using Fernet."""
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return decrypted_data


# Example Usage (Illustrative - replace with secure practices)
if __name__ == '__main__':
    # Create a user (only do this once)
    if createUser("testuser", "P@$$wOrd123"):
        print("User created successfully.")
    else:
        print("User creation failed.")

    # Check the password
    if checkPassword("testuser", "P@$$wOrd123"):
        print("Password is correct.")
    else:
        print("Password is incorrect.")

    # Change the password
    if changePassword("testuser", "NewP@$$wOrd456"):
        print("Password changed successfully.")
    else:
        print("Password change failed.")

    # Verify the new password
    if checkPassword("testuser", "NewP@$$wOrd456"):
        print("New password is correct.")
    else:
        print("New password is incorrect.")

    # Example of encrypting and decrypting data
    sensitive_info = "My Secret Information"
    encrypted_info = encrypt_data(sensitive_info)
    print(f"Encrypted data: {encrypted_info}")
    decrypted_info = decrypt_data(encrypted_info)
    print(f"Decrypted data: {decrypted_info}")

