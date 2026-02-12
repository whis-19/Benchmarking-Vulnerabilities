import mysql.connector
import configparser
import os
import bcrypt
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Read database configuration from a file (e.g., config.ini)
def get_db_config(config_file='config.ini', section='database'):
    """Reads database configuration from a file."""
    config = configparser.ConfigParser()
    config.read(config_file)
    if section not in config:
        raise ValueError(f"Section '{section}' not found in config file '{config_file}'")
    db_config = {}
    for key, value in config.items(section):
        db_config[key] = value
    return db_config

def get_connection():
    """
    Return a connection to the database using configuration from file.
    Handles connection limits.
    """
    try:
        db_config = get_db_config()
        connection = mysql.connector.connect(**db_config)
        return connection
    except mysql.connector.Error as err:
        logging.error(f"Error connecting to database: {err}")
        print(f"Error connecting to database: {err}")
        return None
    except ValueError as err:
        logging.error(f"Error reading configuration: {err}")
        print(f"Error reading configuration: {err}")
        return None
    except Exception as err:
        logging.error(f"An unexpected error occurred: {err}")
        print(f"An unexpected error occurred: {err}")
        return None


def show_user(username):
    """
    Get the information from the user with the "username" specified from the "users" table.
    Return the user information.  Uses prepared statements to prevent SQL injection.
    """
    connection = get_connection()
    if connection is None:
        return None

    try:
        cursor = connection.cursor()
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))  # Use parameterized query
        result = cursor.fetchone()
        if result:
            logging.info(f"User '{username}' information retrieved successfully.")
        else:
            logging.warning(f"User '{username}' not found.")
        return result
    except mysql.connector.Error as err:
        logging.error(f"Error executing query: {err}")
        print(f"Error executing query: {err}")
        return None
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def hash_password(password):
    """Hashes a password using bcrypt."""
    password = password.encode('utf-8')
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string

def verify_password(password, hashed_password):
    """Verifies a password against a bcrypt hash."""
    password = password.encode('utf-8')
    hashed_password = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password, hashed_password)

def validate_username(username):
    """Validates a username."""
    if not (3 <= len(username) <= 50):
        return False, "Username must be between 3 and 50 characters."
    if not re.match("^[a-zA-Z0-9_]+$", username):  # Allow underscores
        return False, "Username must contain only alphanumeric characters and underscores."
    return True, None

def validate_password(password, config_file='config.ini', section='password_policy'):
    """Validates a password based on configurable complexity requirements."""
    config = configparser.ConfigParser()
    config.read(config_file)

    if section not in config:
        logging.warning(f"Password policy section '{section}' not found in config file '{config_file}'. Using default password policy.")
        min_length = 8
        max_length = 100
        require_uppercase = True
        require_lowercase = True
        require_digit = True
        require_special = True
    else:
        try:
            min_length = config.getint(section, 'min_length', fallback=8)
            max_length = config.getint(section, 'max_length', fallback=100)
            require_uppercase = config.getboolean(section, 'require_uppercase', fallback=True)
            require_lowercase = config.getboolean(section, 'require_lowercase', fallback=True)
            require_digit = config.getboolean(section, 'require_digit', fallback=True)
            require_special = config.getboolean(section, 'require_special', fallback=True)
        except ValueError as e:
            logging.error(f"Error reading password policy from config file: {e}. Using default password policy.")
            min_length = 8
            max_length = 100
            require_uppercase = True
            require_lowercase = True
            require_digit = True
            require_special = True


    if not (min_length <= len(password) <= max_length):
        return False, f"Password must be between {min_length} and {max_length} characters."

    if require_uppercase and not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if require_lowercase and not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if require_digit and not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if require_special and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."

    return True, None


def create_user(username, password):
    """
    Creates a new user in the database.  Hashes the password and uses prepared statements.
    Also implements a "first login" mode by requiring a password change on first login.
    """
    connection = get_connection()
    if connection is None:
        return False

    is_username_valid, username_error = validate_username(username)
    if not is_username_valid:
        logging.warning(f"User creation failed for '{username}': {username_error}")
        print(username_error)
        return False

    is_password_valid, password_error = validate_password(password)
    if not is_password_valid:
        logging.warning(f"User creation failed for '{username}': {password_error}")
        print(password_error)
        return False


    try:
        cursor = connection.cursor()

        # Hash the password using bcrypt
        hashed_password = hash_password(password)

        # Insert the user into the database
        query = "INSERT INTO users (username, password, first_login) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, hashed_password, True))  # Mark as first login
        connection.commit()

        logging.info(f"User '{username}' created successfully.")
        print(f"User '{username}' created successfully.")
        return True

    except mysql.connector.Error as err:
        logging.error(f"Error creating user '{username}': {err}")
        print(f"Error creating user: {err}")
        connection.rollback()
        return False
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def change_password(username, old_password, new_password):
    """
    Changes the user's password.  Requires the old password for verification.
    """
    connection = get_connection()
    if connection is None:
        return False

    is_password_valid, password_error = validate_password(new_password)
    if not is_password_valid:
        logging.warning(f"Password change failed for '{username}': {password_error}")
        print(password_error)
        return False

    try:
        cursor = connection.cursor()

        # Verify the old password
        query = "SELECT password FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()

        if result is None:
            logging.warning(f"Password change failed for '{username}': User not found.")
            print("User not found.")
            return False

        stored_password = result[0]

        if not verify_password(old_password, stored_password):
            logging.warning(f"Password change failed for '{username}': Incorrect old password.")
            print("Incorrect old password.")
            return False

        # Hash the new password
        hashed_new_password = hash_password(new_password)

        # Update the password in the database
        query = "UPDATE users SET password = %s, first_login = %s WHERE username = %s"
        cursor.execute(query, (hashed_new_password, False, username)) # Set first_login to False
        connection.commit()

        logging.info(f"Password changed successfully for user '{username}'.")
        print("Password changed successfully.")
        return True

    except mysql.connector.Error as err:
        logging.error(f"Error changing password for '{username}': {err}")
        print(f"Error changing password: {err}")
        connection.rollback()
        return False
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


def check_first_login(username):
    """
    Checks if the user needs to change their password on first login.
    """
    connection = get_connection()
    if connection is None:
        return False

    try:
        cursor = connection.cursor()
        query = "SELECT first_login FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()

        if result is None:
            logging.warning(f"First login check failed for '{username}': User not found.")
            print("User not found.")
            return False

        first_login = result[0]
        logging.info(f"First login status for user '{username}': {first_login}")
        return first_login  # Returns True or False

    except mysql.connector.Error as err:
        logging.error(f"Error checking first login status for '{username}': {err}")
        print(f"Error checking first login status: {err}")
        return False
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()


# Example Usage (assuming you have a config.ini file)
if __name__ == '__main__':
    # Create a config.ini file with the following structure:
    # [database]
    # host = localhost
    # user = your_db_user
    # password = your_db_password
    # database = your_db_name
    #
    # [password_policy]
    # min_length = 8
    # max_length = 100
    # require_uppercase = True
    # require_lowercase = True
    # require_digit = True
    # require_special = True


    # Example 1: Create a new user
    if create_user("testuser", "P@$$wOrd123"):
        print("User created successfully.")

    # Example 2: Check if the user needs to change password on first login
    if check_first_login("testuser"):
        print("User needs to change password on first login.")
    else:
        print("User does not need to change password on first login.")

    # Example 3: Change the password
    if change_password("testuser", "P@$$wOrd123", "NewP@$$wOrd"):
        print("Password changed successfully.")

    # Example 4: Show user information
    user_info = show_user("testuser")
    if user_info:
        print("User information:", user_info)
    else:
        print("User not found or error occurred.")

    # Example 5: Attempt to create a user with an invalid username
    if not create_user("inval!d", "ValidPassword123!"):
        print("User creation failed due to invalid username.")

    # Example 6: Attempt to create a user with an invalid password
    if not create_user("validuser", "weak"):
        print("User creation failed due to weak password.")

    # Example 7: Attempt to change password with an incorrect old password
    if not change_password("testuser", "wrongpassword", "AnotherValidPassword123!"):
        print("Password change failed due to incorrect old password.")

    # Example 8: Demonstrate configurable password policy
    is_valid, message = validate_password("WeakPass", config_file="config.ini")
    print(f"Password 'WeakPass' validation: {is_valid}, Message: {message}")

