import base64
import MySQLdb
import bcrypt
import os

# Securely retrieve database credentials from environment variables
DB_HOST = os.environ.get("DB_HOST")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_NAME = os.environ.get("DB_NAME")


def checkPassword(userid, password):
    """
    Get the hashed password of the userid from the database and compare with the provided one using bcrypt.
    """

    if not all([DB_HOST, DB_USER, DB_PASSWORD, DB_NAME]):
        print("Error: Database credentials not properly configured in environment variables.")
        return False  # Or raise an exception

    try:
        # Establish a database connection
        db = MySQLdb.connect(host=DB_HOST, user=DB_USER, passwd=DB_PASSWORD, db=DB_NAME, ssl_mode="DISABLED")  # Consider SSL if supported

        # Create a cursor object using parameterized query to prevent SQL injection
        cursor = db.cursor()
        query = "SELECT password_hash FROM users WHERE userid = %s"
        cursor.execute(query, (userid,))

        # Fetch the result
        result = cursor.fetchone()

        if result:
            hashed_password = result[0]

            # Verify the password using bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                return True
            else:
                return False
        else:
            # User not found
            return False

    except MySQLdb.Error as e:
        print(f"Database error: {e}")
        return False  # Or raise an exception

    finally:
        # Ensure the connection is closed
        if db:
            db.close()


def hash_password(password):
    """
    Hashes the password using bcrypt.
    """
    # Generate a salt
    salt = bcrypt.gensalt()

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed_password.decode('utf-8')  # Store as string in the database


# Example usage (for demonstration purposes only - do NOT hardcode passwords)
if __name__ == '__main__':
    # Example: Creating a new user and storing the hashed password
    new_password = "MySecurePassword123!"
    hashed_password = hash_password(new_password)
    print(f"Hashed password: {hashed_password}")

    # Example: Checking a password
    user_id = "testuser"  # Replace with a valid user ID from your database
    # Assuming you have a user with userid 'testuser' and the hashed password stored in the database
    # You would insert the hashed_password into the 'users' table in the 'password_hash' column.

    # For testing, let's assume the hashed password for 'testuser' is the one we just generated.
    # In a real application, you would retrieve it from the database.

    # Now, let's check if the password is correct
    is_correct = checkPassword(user_id, new_password)
    if is_correct:
        print("Password is correct!")
    else:
        print("Password is incorrect.")

