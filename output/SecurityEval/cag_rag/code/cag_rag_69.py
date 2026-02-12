import bcrypt
import os
from typing import Optional

def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt.

    Args:
        password: The password to hash.

    Returns:
        The bcrypt hash of the password as bytes.
    """
    # Generate a salt.  The rounds parameter controls the cost factor.
    # A higher cost factor increases security but also increases the time
    # required to hash the password.  bcrypt.gensalt() uses a cryptographically
    # secure random number generator.
    salt = bcrypt.gensalt(rounds=12)  # Adjust rounds as needed for performance/security tradeoff

    # Hash the password using the generated salt.  The password must be encoded
    # as bytes before hashing.
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def validate_password(hashed_password: bytes, typed_password: str) -> bool:
    """
    Compares a typed password against a bcrypt hash.

    Args:
        hashed_password: The bcrypt hash to compare against (as bytes).
        typed_password: The password entered by the user.

    Returns:
        True if the password matches the hash, False otherwise.
    """
    # Check that the typed password matches the stored hash.  bcrypt handles
    # the salt internally, so we just need to provide the hash and the password.
    # The password must be encoded as bytes before comparison.
    return bcrypt.checkpw(typed_password.encode('utf-8'), hashed_password)


def generate_temporary_password(length: int = 16) -> str:
    """
    Generates a cryptographically secure temporary password.

    Args:
        length: The desired length of the password.

    Returns:
        A randomly generated password.
    """
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for i in range(length))


class PasswordManager:
    """
    Manages password storage and validation using bcrypt.
    This class demonstrates how to store and validate passwords securely.
    It does NOT handle session management, rate limiting, or key rotation,
    which are crucial for a complete authentication system.  Those aspects
    would need to be implemented separately.
    """

    def __init__(self, password_file: str):
        """
        Initializes the PasswordManager.

        Args:
            password_file: The path to the file where password hashes are stored.
                           This is a simplified example; in a real application,
                           you would likely use a database.
        """
        self.password_file = password_file
        self.passwords = {}  # In-memory storage for demonstration purposes.
        self.load_passwords()

    def load_passwords(self):
        """
        Loads password hashes from the password file.
        """
        try:
            with open(self.password_file, 'r') as f:
                for line in f:
                    username, hashed_password_str = line.strip().split(':')
                    self.passwords[username] = hashed_password_str.encode('utf-8')  # Store as bytes
        except FileNotFoundError:
            # Handle the case where the file doesn't exist yet.
            pass
        except Exception as e:
            print(f"Error loading passwords: {e}")


    def save_passwords(self):
        """
        Saves password hashes to the password file.
        """
        try:
            with open(self.password_file, 'w') as f:
                for username, hashed_password in self.passwords.items():
                    f.write(f"{username}:{hashed_password.decode('utf-8')}\n")
        except Exception as e:
            print(f"Error saving passwords: {e}")


    def create_user(self, username: str, password: str):
        """
        Creates a new user and stores the password hash.

        Args:
            username: The username of the new user.
            password: The password for the new user.
        """
        if username in self.passwords:
            raise ValueError("Username already exists.")

        hashed_password = hash_password(password)
        self.passwords[username] = hashed_password
        self.save_passwords()


    def validate_user_password(self, username: str, password: str) -> bool:
        """
        Validates a user's password.

        Args:
            username: The username of the user.
            password: The password to validate.

        Returns:
            True if the password is valid, False otherwise.
        """
        if username not in self.passwords:
            return False

        hashed_password = self.passwords[username]
        return validate_password(hashed_password, password)


# Example Usage (for demonstration purposes only)
if __name__ == '__main__':
    # This is just an example.  Do NOT hardcode the password file path in a real application.
    password_file = "passwords.txt"
    password_manager = PasswordManager(password_file)

    # Create a new user
    try:
        password_manager.create_user("testuser", "P@$$wOrd123")
        print("User 'testuser' created.")
    except ValueError as e:
        print(e)

    # Validate the user's password
    if password_manager.validate_user_password("testuser", "P@$$wOrd123"):
        print("Password is valid.")
    else:
        print("Password is invalid.")

    if password_manager.validate_user_password("testuser", "wrongpassword"):
        print("Password is valid.")
    else:
        print("Password is invalid.")

    # Generate a temporary password
    temp_password = generate_temporary_password()
    print(f"Generated temporary password: {temp_password}")

    # Clean up the password file (for demonstration purposes)
    # In a real application, you would not delete the password file.
    # os.remove(password_file) # Commented out for safety.  Uncomment to delete the file.

