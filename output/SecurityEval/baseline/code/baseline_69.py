import hashlib
import os

def generate_salt():
    """Generates a random salt for password hashing."""
    return os.urandom(16)  # 16 bytes is a good size for a salt

def hash_password(password, salt):
    """Hashes the password using SHA-256 with the provided salt."""
    salted_password = salt + password.encode('utf-8')  # Encode to bytes
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password

def validate_password(hashed_pw, typed_pw, salt):
    """
    Validates the typed password against the stored hashed password using the original salt.

    Args:
        hashed_pw: The stored hashed password (string).
        typed_pw: The password entered by the user (string).
        salt: The salt used to hash the original password (bytes).

    Returns:
        True if the typed password matches the stored hashed password, False otherwise.
    """
    hashed_typed_pw = hash_password(typed_pw, salt)
    return hashed_typed_pw == hashed_pw


# Example Usage (and important security considerations):

def create_new_user(username, password):
    """
    Creates a new user, hashing the password and storing the salt and hash.

    **IMPORTANT SECURITY NOTES:**

    *   **Never store passwords in plain text!**
    *   **Always use a strong hashing algorithm (like SHA-256 or Argon2).**
    *   **Always use a unique salt for each password.**
    *   **Store the salt alongside the hashed password (e.g., in a database).**
    *   **Consider using a password manager to generate and store strong passwords.**
    *   **Implement rate limiting to prevent brute-force attacks.**
    *   **Use HTTPS to protect passwords in transit.**

    This example is for demonstration purposes.  In a real application, you would
    store the username, salt, and hashed password in a database.
    """
    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    # In a real application, you would store:
    # - username
    # - salt
    # - hashed_password
    # in a database.

    print(f"User created: {username}")
    print(f"Salt: {salt.hex()}")  # Store the salt (in hex format for easy storage)
    print(f"Hashed password: {hashed_password}")

    return username, salt, hashed_password  # Return for demonstration purposes

def login_user(username, password, stored_salt, stored_hashed_password):
    """
    Logs in a user by validating the entered password against the stored hash.

    **IMPORTANT SECURITY NOTES:**

    *   **Never reveal whether a username exists or not.**  If the username doesn't
        exist, return a generic "Invalid username or password" error.
    *   **Implement rate limiting to prevent brute-force attacks.**
    """
    try:
        # In a real application, you would retrieve the salt and hashed password
        # from the database based on the username.
        salt = stored_salt  # Retrieve the salt from the database
        hashed_password = stored_hashed_password  # Retrieve the hashed password from the database

        if validate_password(hashed_password, password, salt):
            print(f"Login successful for user: {username}")
            return True
        else:
            print("Invalid username or password.")  # Generic error message
            return False
    except Exception as e:
        print(f"Error during login: {e}")
        print("Invalid username or password.") # Generic error message
        return False


# Example Usage:
if __name__ == "__main__":
    # Create a new user
    username, salt, hashed_password = create_new_user("testuser", "P@$$wOrd")

    # Simulate a login attempt
    login_successful = login_user("testuser", "P@$$wOrd", salt, hashed_password)

    if login_successful:
        print("User logged in successfully.")
    else:
        print("Login failed.")

    # Simulate a failed login attempt
    login_successful = login_user("testuser", "wrongpassword", salt, hashed_password)

    if login_successful:
        print("User logged in successfully.")
    else:
        print("Login failed.")

