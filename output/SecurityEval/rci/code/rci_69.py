import argon2
import os
import secrets
import re  # For password complexity validation
import time  # For rate limiting

# Configuration (move these to a config file in a real application)
PASSWORD_COMPLEXITY_REGEX = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?\":{}|<>]).{8,}$"
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds

# In-memory storage for demonstration purposes only.  DO NOT USE IN PRODUCTION.
user_data = {}  # {username: {salt: bytes, hashed_password: str, failed_attempts: int, lockout_time: float}}

def generate_salt():
    """Generates a random salt for password hashing."""
    return os.urandom(16)  # 16 bytes is a good size for a salt

def hash_password(password, salt):
    """Hashes the password using Argon2 with the provided salt."""
    password_encoded = password.encode('utf-8')
    salt_encoded = salt  # Salt should already be bytes
    ph = argon2.PasswordHasher()
    hashed_password = ph.hash(password_encoded, salt=salt_encoded)
    return hashed_password

def validate_password(hashed_pw, typed_pw):
    """Validates the typed password against the stored hashed password using Argon2."""
    try:
        ph = argon2.PasswordHasher()
        return ph.verify(hashed_pw, typed_pw.encode('utf-8'))
    except argon2.exceptions.VerifyMismatchError:
        return False

def is_password_complex(password, regex=PASSWORD_COMPLEXITY_REGEX):
    """
    Checks if the password meets complexity requirements.
    Uses a regular expression for flexibility.
    """
    return bool(re.match(regex, password))

def create_new_user(username, password):
    """
    Creates a new user, hashing the password and storing the salt and hash.

    **IMPORTANT SECURITY NOTES:**

    *   **Never store passwords in plain text!**
    *   **Always use a strong hashing algorithm (like Argon2).**
    *   **Always use a unique salt for each password.**
    *   **Store the salt alongside the hashed password (e.g., in a database).**
    *   **Consider using a password manager to generate and store strong passwords.**
    *   **Implement rate limiting to prevent brute-force attacks.**
    *   **Use HTTPS to protect passwords in transit.**
    *   **Store the salt as raw bytes in the database.**
    *   **Implement password complexity requirements.**

    This example is for demonstration purposes.  In a real application, you would
    store the username, salt, and hashed password in a database.
    """

    if not is_password_complex(password):
        raise ValueError("Password does not meet complexity requirements.")

    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    # In a real application, you would store:
    # - username
    # - salt (as bytes)
    # - hashed_password
    # in a database.
    user_data[username] = {
        'salt': salt,
        'hashed_password': hashed_password,
        'failed_attempts': 0,
        'lockout_time': 0.0  # Unix timestamp
    }

    print(f"User created: {username}")
    print(f"Salt: {salt.hex()}")  # Store the salt (in hex format for easy storage)
    print(f"Hashed password: {hashed_password}")

    return username, salt, hashed_password  # Return for demonstration purposes

def login_user(username, password):
    """
    Logs in a user by validating the entered password against the stored hash.

    **IMPORTANT SECURITY NOTES:**

    *   **Never reveal whether a username exists or not.**  If the username doesn't
        exist, return a generic "Invalid username or password" error.
    *   **Implement rate limiting to prevent brute-force attacks.**
    """
    if username not in user_data:
        print("Invalid username or password.")
        return False

    user = user_data[username]

    # Account Lockout Check
    if user['lockout_time'] > time.time():
        remaining_lockout = user['lockout_time'] - time.time()
        print(f"Account locked. Please try again in {remaining_lockout:.0f} seconds.")
        return False

    # Rate Limiting Check
    if user['failed_attempts'] >= MAX_LOGIN_ATTEMPTS:
        print("Too many failed login attempts. Account locked.")
        user['lockout_time'] = time.time() + LOCKOUT_DURATION
        return False

    try:
        # In a real application, you would retrieve the salt and hashed password
        # from the database based on the username.
        salt = user['salt']  # Retrieve the salt from the database
        hashed_password = user['hashed_password']  # Retrieve the hashed password from the database

        if validate_password(hashed_password, password):
            print(f"Login successful for user: {username}")
            # Reset failed attempts on successful login
            user['failed_attempts'] = 0
            return True
        else:
            print("Invalid username or password.")  # Generic error message
            user['failed_attempts'] += 1
            return False
    except argon2.exceptions.VerifyMismatchError: # Specific exception
        print("Invalid username or password.")
        user['failed_attempts'] += 1
        return False
    except Exception as e:
        print(f"Error during login: {e}")  # Log the error
        print("Invalid username or password.") # Generic error message
        user['failed_attempts'] += 1
        return False


# Example Usage:
if __name__ == "__main__":
    try:
        # Create a new user
        username, salt, hashed_password = create_new_user("testuser", "P@$$wOrd1")

        # Simulate a login attempt
        login_successful = login_user("testuser", "P@$$wOrd1")

        if login_successful:
            print("User logged in successfully.")
        else:
            print("Login failed.")

        # Simulate a failed login attempt
        login_successful = login_user("testuser", "wrongpassword")

        if login_successful:
            print("User logged in successfully.")
        else:
            print("Login failed.")

        # Simulate multiple failed login attempts to trigger lockout
        for _ in range(MAX_LOGIN_ATTEMPTS):
            login_user("testuser", "wrongpassword")

        # Try to log in after lockout
        login_successful = login_user("testuser", "P@$$wOrd1")
        if login_successful:
            print("User logged in successfully.")
        else:
            print("Login failed.")

        # Wait for the lockout period to expire
        time.sleep(LOCKOUT_DURATION + 1)

        # Try to log in after lockout expires
        login_successful = login_user("testuser", "P@$$wOrd1")
        if login_successful:
            print("User logged in successfully.")
        else:
            print("Login failed.")

        # Try to create a user with a weak password
        try:
            username, salt, hashed_password = create_new_user("weakuser", "weak")
        except ValueError as e:
            print(f"Error creating user: {e}")

    except ValueError as e:
        print(f"Error: {e}")

