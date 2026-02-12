import hashlib
import os
import secrets
import subprocess
import time

from typing import Dict, Any, List

# --- Security Configuration ---
ALLOWED_COMMANDS = ['login', 'retrieve_file', 'list_files']
LOGIN_ATTEMPT_WINDOW = 60  # seconds
MAX_LOGIN_ATTEMPTS = 5
PASSWORD_SALT_LENGTH = 16
# --- End Security Configuration ---

# --- Data Storage (Replace with secure database) ---
USER_DATABASE: Dict[str, Dict[str, Any]] = {}  # username: {salt, hashed_password, login_attempts, last_attempt}
FILE_DATABASE: Dict[str, str] = {}  # filename: filepath
# --- End Data Storage ---


def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Hashes the password using PBKDF2-HMAC with a random salt."""
    if salt is None:
        salt = secrets.token_bytes(PASSWORD_SALT_LENGTH)  # Generate a new salt
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000  # Recommended number of iterations
    )
    return salt, hashed_password


def verify_password(password: str, salt: bytes, hashed_password: bytes) -> bool:
    """Verifies the password against the stored hash and salt."""
    new_hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return secrets.compare_digest(new_hashed_password, hashed_password)


def loginUser(username: str, password: str) -> bool:
    """Authenticates the user and manages login attempts."""
    user_data = USER_DATABASE.get(username)

    if user_data is None:
        return False  # User does not exist

    now = time.time()
    if user_data.get('login_attempts', 0) >= MAX_LOGIN_ATTEMPTS and \
            now - user_data.get('last_attempt', 0) < LOGIN_ATTEMPT_WINDOW:
        print(f"Too many login attempts for user {username}.  Please wait.")
        return False  # Rate limiting

    salt = user_data['salt']
    hashed_password = user_data['hashed_password']

    if verify_password(password, salt, hashed_password):
        # Reset login attempts on successful login
        user_data['login_attempts'] = 0
        user_data['last_attempt'] = 0
        print(f"User {username} logged in successfully.")
        return True
    else:
        # Increment login attempts
        user_data['login_attempts'] = user_data.get('login_attempts', 0) + 1
        user_data['last_attempt'] = now
        print(f"Login failed for user {username}.  Attempt {user_data['login_attempts']}/{MAX_LOGIN_ATTEMPTS}")
        return False


def sendFile(filename: str, user: str) -> bytes | None:
    """Retrieves and returns the file content (simulated)."""
    # Authentication/Authorization check (replace with proper implementation)
    if not authenticate_user_for_file(user, filename):
        print(f"User {user} is not authorized to access file {filename}.")
        return None

    filepath = FILE_DATABASE.get(filename)
    if not filepath:
        print(f"File {filename} not found.")
        return None

    try:
        with open(filepath, 'rb') as f:
            file_content = f.read()
        return file_content
    except FileNotFoundError:
        print(f"File {filename} not found at path {filepath}.")
        return None
    except Exception as e:
        print(f"Error reading file {filename}: {e}")
        return None


def listFiles(user: str) -> List[str]:
    """Lists files accessible to the user (simulated)."""
    # Authentication/Authorization check (replace with proper implementation)
    if not authenticate_user_for_listing(user):
        print(f"User {user} is not authorized to list files.")
        return []

    # In a real system, this would query a database or file system
    # to determine the files accessible to the user.
    accessible_files = list(FILE_DATABASE.keys())  # Simulate access
    return accessible_files


def authenticate_user_for_file(user: str, filename: str) -> bool:
    """Simulates authentication/authorization for file access."""
    # Replace with a real authentication/authorization mechanism
    # based on user roles, permissions, etc.
    # This is a placeholder for demonstration purposes.
    return True  # Allow all users for now


def authenticate_user_for_listing(user: str) -> bool:
    """Simulates authentication/authorization for file listing."""
    # Replace with a real authentication/authorization mechanism.
    return True  # Allow all users for now


def dispatchCommand(command: str, user: str, args: List[str]) -> Any:
    """
    This function checks the command data and calls the appropriate function.
    """
    if not isinstance(command, str):
        print("Invalid command type.")
        return None

    if command not in ALLOWED_COMMANDS:
        print(f"Invalid command: {command}")
        return None

    if not isinstance(user, str):
        print("Invalid user type.")
        return None

    if not isinstance(args, list):
        print("Invalid arguments type.")
        return None

    # Input validation and sanitization
    sanitized_args = []
    for arg in args:
        if not isinstance(arg, str):
            print("Invalid argument type.")
            return None
        sanitized_args.append(escape_string(arg))  # Escape potentially dangerous characters

    if command == 'login':
        if len(sanitized_args) != 2:
            print("Login requires a username and password.")
            return False
        username = sanitized_args[0]
        password = sanitized_args[1]
        return loginUser(username, password)

    elif command == 'retrieve_file':
        if len(sanitized_args) != 1:
            print("retrieve_file requires a filename.")
            return None
        filename = sanitized_args[0]
        return sendFile(filename, user)

    elif command == 'list_files':
        return listFiles(user)

    else:
        print(f"Unknown command: {command}")
        return None


def escape_string(input_string: str) -> str:
    """
    Escapes potentially dangerous characters in a string to prevent command injection.
    This is a basic example and might need to be adapted based on the specific context.
    """
    # Use a library routine for escaping if possible.  For example, shlex.quote
    # if you are passing the string to a shell command.
    # This example provides a basic escaping mechanism.
    escaped_string = input_string.replace("'", "'\\''").replace('"', '\\"')
    return escaped_string


# --- Example Usage ---
if __name__ == '__main__':
    # --- Setup (Replace with secure user registration) ---
    # First login scenario: create a new user
    if 'testuser' not in USER_DATABASE:
        # Simulate first login: require a strong password
        initial_password = "StrongPassword123!"  # Replace with user input
        salt, hashed_password = hash_password(initial_password)
        USER_DATABASE['testuser'] = {
            'salt': salt,
            'hashed_password': hashed_password,
            'login_attempts': 0,
            'last_attempt': 0
        }

    # Add a file to the database
    FILE_DATABASE['my_document.txt'] = 'path/to/my_document.txt'  # Replace with actual path
    # --- End Setup ---

    # Example 1: Successful login
    result = dispatchCommand('login', 'testuser', ['testuser', 'StrongPassword123!'])
    print(f"Login result: {result}")

    # Example 2: Failed login (wrong password)
    result = dispatchCommand('login', 'testuser', ['testuser', 'wrong_password'])
    print(f"Login result: {result}")

    # Example 3: Retrieve file
    result = dispatchCommand('retrieve_file', 'testuser', ['my_document.txt'])
    print(f"Retrieve file result: {result}")

    # Example 4: List files
    result = dispatchCommand('list_files', 'testuser', [])
    print(f"List files result: {result}")

    # Example 5: Invalid command
    result = dispatchCommand('invalid_command', 'testuser', [])
    print(f"Invalid command result: {result}")

    # Example 6: Command injection attempt (prevented by escaping)
    result = dispatchCommand('retrieve_file', 'testuser', ["file'; rm -rf /; '"])
    print(f"Command injection attempt result: {result}")

