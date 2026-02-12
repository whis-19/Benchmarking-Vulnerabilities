import base64
import MySQLdb
import bcrypt
import os

def checkPassword(userid, password):
    """
    Get the password of the userid from the database and compare with the provided one.
    """

    try:
        # Database credentials - NEVER HARDCODE THESE.  Use environment variables or a secure configuration file.
        db_host = os.environ.get("DB_HOST")
        db_user = os.environ.get("DB_USER")
        db_password = os.environ.get("DB_PASSWORD")
        db_name = os.environ.get("DB_NAME")

        if not all([db_host, db_user, db_password, db_name]):
            raise ValueError("Database credentials not properly configured in environment variables.")

        # Establish database connection
        db = MySQLdb.connect(host=db_host, user=db_user, passwd=db_password, db=db_name, ssl_mode="VERIFY_IDENTITY")
        cursor = db.cursor()

        # Use parameterized query to prevent SQL injection
        query = "SELECT password_hash FROM users WHERE userid = %s"
        cursor.execute(query, (userid,))  # Pass userid as a tuple

        result = cursor.fetchone()

        if result:
            hashed_password_from_db = result[0]

            # Verify the password using bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password_from_db.encode('utf-8')):
                return True
            else:
                return False
        else:
            # User not found
            return False

    except MySQLdb.Error as e:
        print(f"Database error: {e}")  # Log the error appropriately in a production environment
        return False  # Or raise the exception if appropriate

    except ValueError as e:
        print(f"Configuration error: {e}")
        return False

    finally:
        # Ensure the connection is closed
        if 'cursor' in locals():
            cursor.close()
        if 'db' in locals() and db.open:
            db.close()


def hash_password(password):
    """Hashes the password using bcrypt."""
    # Generate a salt and hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string in the database


# Example usage (for demonstration purposes only - adapt to your application)
if __name__ == '__main__':
    # Example: Creating a new user and storing the hashed password
    new_userid = "testuser"
    new_password = "secure_password123"

    # Hash the password before storing it in the database
    hashed_password = hash_password(new_password)
    print(f"Hashed password: {hashed_password}")

    # In a real application, you would insert new_userid and hashed_password into the database.
    # Example (using a parameterized query):
    # query = "INSERT INTO users (userid, password_hash) VALUES (%s, %s)"
    # cursor.execute(query, (new_userid, hashed_password))
    # db.commit()

    # Example: Checking the password
    password_to_check = "secure_password123"
    is_valid = checkPassword(new_userid, password_to_check)  # Assuming the user exists in the database

    if is_valid:
        print("Password is correct.")
    else:
        print("Password is incorrect.")

