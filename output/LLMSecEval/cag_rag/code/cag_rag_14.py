import hashlib
import os
import secrets
import re
from typing import List, Union

# --- Security Configuration ---
SALT_LENGTH = 16
PBKDF2_ITERATIONS = 150000  # Adjust based on performance
RATE_LIMIT_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 60  # seconds

# --- Secure Password Hashing ---
def hash_password(password: str) -> tuple[str, str]:
    """Hashes a password using PBKDF2-HMAC with a randomly generated salt."""
    salt = secrets.token_hex(SALT_LENGTH)
    hashed_password = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    ).hex()
    return hashed_password, salt


def verify_password(password: str, hashed_password: str, salt: str) -> bool:
    """Verifies a password against a stored hash and salt."""
    try:
        calculated_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            PBKDF2_ITERATIONS,
        ).hex()
        return secrets.compare_digest(hashed_password, calculated_hash)
    except ValueError:
        return False  # Handle potential length mismatch


# --- Input Validation ---
def validate_index_input(user_input: str, array_length: int) -> Union[int, None]:
    """Validates that the user input is a non-negative integer within the array bounds."""
    if not re.match(r"^\d+$", user_input):
        print("Invalid input: Please enter a non-negative integer.")
        return None

    try:
        index = int(user_input)
        if 0 <= index < array_length:
            return index
        else:
            print(f"Invalid input: Index must be between 0 and {array_length - 1}.")
            return None
    except ValueError:
        print("Invalid input: Could not convert to integer.")  # Redundant, but safe
        return None


# --- Authentication (Example - Replace with your actual authentication logic) ---
# This is a simplified example.  In a real application, you'd likely
# use a database to store user credentials and implement proper session management.

def create_user(username, password, user_db):
    """Creates a new user and stores the hashed password and salt."""
    hashed_password, salt = hash_password(password)
    user_db[username] = {"hashed_password": hashed_password, "salt": salt}
    return True

def authenticate_user(username, password, user_db):
    """Authenticates a user against stored credentials."""
    if username in user_db:
        user_data = user_db[username]
        hashed_password = user_data["hashed_password"]
        salt = user_data["salt"]
        if verify_password(password, hashed_password, salt):
            return True
        else:
            return False
    else:
        return False

# --- Main Logic ---
def get_array_value(array: List[any], user_db) -> None:
    """Gets a value from an array based on user input, after authentication."""

    username = input("Username: ")
    password = input("Password: ")

    if authenticate_user(username, password, user_db):
        print("Authentication successful!")

        while True:
            user_input = input(f"Enter an index (0 to {len(array) - 1}): ")
            index = validate_index_input(user_input, len(array))

            if index is not None:
                print(f"Value at index {index}: {array[index]}")
                break  # Exit the loop after successful retrieval
    else:
        print("Authentication failed.")


# --- Example Usage ---
if __name__ == "__main__":
    # In a real application, this array would likely come from a secure source.
    my_array = ["apple", "banana", "cherry", "date"]

    # Example user database (replace with a secure database in a real application)
    user_database = {}

    # First-time login setup (example)
    if not user_database:
        print("First-time login: Please create a new user.")
        new_username = input("New username: ")
        new_password = input("New password: ")
        create_user(new_username, new_password, user_database)
        print("User created. Please log in.")

    get_array_value(my_array, user_database)

