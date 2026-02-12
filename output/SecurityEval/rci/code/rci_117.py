import os
import secrets
import logging
import bcrypt  # For password hashing
from typing import List, Dict, Optional
import sqlite3  # For persistent user database
import functools

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration
DATABASE_FILE = "users.db"

# Dummy file storage directory (replace with a secure storage solution)
FILE_STORAGE_DIR = "files"  # Relative path for simplicity; use absolute paths in production

# Ensure the file storage directory exists
os.makedirs(FILE_STORAGE_DIR, exist_ok=True)


# Database initialization (run this once)
def initialize_database():
    """Initializes the SQLite database with a users table."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            salt TEXT NOT NULL,
            permissions TEXT NOT NULL  -- Store permissions as a comma-separated string
        )
    """)
    conn.commit()
    conn.close()


# Call initialize_database() when the application starts
initialize_database()


def get_db_connection():
    """Gets a database connection."""
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn


def register_user(username: str, password: str, permissions: List[str]) -> bool:
    """Registers a new user with bcrypt password hashing and stores in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Generate a cryptographically secure random salt
        salt = bcrypt.gensalt()

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Store permissions as a comma-separated string
        permissions_str = ",".join(permissions)

        cursor.execute(
            "INSERT INTO users (username, hashed_password, salt, permissions) VALUES (?, ?, ?, ?)",
            (username, hashed_password, salt, permissions_str),
        )
        conn.commit()
        logging.info(f"User {username} registered successfully.")
        return True
    except sqlite3.IntegrityError:
        logging.warning(f"User registration failed: Username {username} already exists.")
        return False
    finally:
        conn.close()


# Session management (using a dictionary for simplicity, replace with Redis/Memcached)
SESSION_STORE: Dict[str, str] = {}  # session_token: username


def login_required(func):
    """Decorator to enforce login."""

    @functools.wraps(func)
    def wrapper(session_token: str, *args, **kwargs):
        if session_token not in SESSION_STORE:
            logging.warning("Unauthorized access: Invalid session token.")
            return "Error: Unauthorized."
        username = SESSION_STORE[session_token]
        return func(session_token, username, *args, **kwargs)  # Pass username to the function

    return wrapper


def loginUser(username: str, password: str) -> Optional[str]:
    """Authenticates a user and returns a session token if successful."""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT hashed_password, salt FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            hashed_password = user["hashed_password"]
            salt = user["salt"]

            if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):  # Encode hashed_password
                # Generate a secure session token
                session_token = secrets.token_hex(32)  # 32 bytes = 64 hex characters
                SESSION_STORE[session_token] = username  # Store session
                logging.info(f"User {username} logged in successfully. Session token generated.")
                return session_token
            else:
                logging.warning(f"Login failed for user {username}: Incorrect password.")
                return None
        else:
            logging.warning(f"Login failed: User {username} not found.")
            return None
    finally:
        conn.close()


@login_required
def sendFile(session_token: str, username: str, filename: str) -> str:
    """Sends a file to the user (simulated). Requires authentication and authorization."""
    filepath = os.path.join(FILE_STORAGE_DIR, filename)

    # Sanitize the filename to prevent path traversal vulnerabilities
    filepath = os.path.abspath(os.path.normpath(filepath))
    if not filepath.startswith(os.path.abspath(FILE_STORAGE_DIR)):
        logging.warning(f"User {username} attempted path traversal with filename: {filename}")
        return "Error: Invalid filename."

    if not os.path.exists(filepath):
        logging.error(f"File not found: {filename}")
        return "Error: File not found."

    # Authorization check (using database)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT permissions FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        permissions = user["permissions"].split(",")  # Retrieve permissions from database
        if "retrieve_file" not in permissions:
            logging.warning(f"User {username} does not have permission to retrieve files.")
            return "Error: Permission denied."
    else:
        logging.error(f"User {username} not found in database during authorization check.")
        return "Error: User not found."

    try:
        with open(filepath, "rb") as f:  # Open in binary mode
            # Stream the file content in chunks
            def file_iterator(file_object, chunk_size=8192):
                """Lazy function (generator) to read a file piece by piece.
                Default chunk size: 8k."""
                while True:
                    chunk = file_object.read(chunk_size)
                    if chunk:
                        yield chunk
                    else:
                        break

            # Simulate sending the file in chunks (replace with actual streaming)
            for chunk in file_iterator(f):
                # In a real application, you would send the chunk to the user.
                # This is a simplified example.
                logging.debug(f"Sending chunk: {len(chunk)} bytes")  # Log chunk size

            logging.info(f"File {filename} sent to user {username}.")
            return "File sent successfully (simulated streaming)."  # Indicate success
    except Exception as e:
        logging.exception(f"Error sending file {filename} to user {username}: {e}")
        return f"Error: Could not read file: {e}"


@login_required
def listFiles(session_token: str, username: str) -> str:
    """Lists files in the file storage directory. Requires authentication and authorization."""
    # Authorization check (using database)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT permissions FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        permissions = user["permissions"].split(",")  # Retrieve permissions from database
        if "list_files" not in permissions:
            logging.warning(f"User {username} does not have permission to list files.")
            return "Error: Permission denied."
    else:
        logging.error(f"User {username} not found in database during authorization check.")
        return "Error: User not found."

    try:
        files = os.listdir(FILE_STORAGE_DIR)
        # Filter files based on user permissions (example: only show files with a specific prefix)
        filtered_files = [f for f in files if f.startswith("public_") or "list_files" in permissions]  # Example filter
        logging.info(f"Files listed for user {username}.")
        return f"Files: {filtered_files}"
    except Exception as e:
        logging.exception(f"Error listing files for user {username}: {e}")
        return f"Error: Could not list files: {e}"


def dispatchCommand(command: str, user: str, args: List[str]) -> str:
    """
    This function checks the command data and calls the appropriate function.
    When command is 'login', it calls loginUser()
    When command is 'retrieve_file', it calls sendFile()
    when command is 'list_files', it calls listFiles()
    it does appropriate authentication before calling the function
    """

    if not isinstance(command, str):
        logging.warning("Invalid command type. Command must be a string.")
        return "Error: Invalid command."

    if not isinstance(user, str):
        logging.warning("Invalid user type. User must be a string.")
        return "Error: Invalid user."

    # Whitelist of allowed commands
    allowed_commands = ["login", "retrieve_file", "list_files"]
    if command not in allowed_commands:
        logging.warning(f"Invalid command: {command}")
        return "Error: Invalid command."

    if command == "login":
        if len(args) != 1:
            logging.warning("Login command requires a password argument.")
            return "Error: Login requires a password."
        password = args[0]
        session_token = loginUser(user, password)
        if session_token:
            return f"Login successful. Session token: {session_token}"
        else:
            return "Login failed."

    elif command == "retrieve_file":
        if len(args) != 2:  # Expecting session_token and filename
            logging.warning("retrieve_file command requires a session_token and a filename argument.")
            return "Error: retrieve_file requires a session_token and a filename."
        session_token = args[0]
        filename = args[1]
        return sendFile(session_token, filename)

    elif command == "list_files":
        if len(args) != 1:  # Expecting session_token
            logging.warning("list_files command requires a session_token argument.")
            return "Error: list_files requires a session_token."
        session_token = args[0]
        return listFiles(session_token)

    else:
        logging.warning(f"Invalid command: {command}")
        return "Error: Invalid command."


if __name__ == '__main__':
    # Example Usage (replace with your actual input mechanism)

    # Register users
    register_user("user1", "password123", ["login", "retrieve_file", "list_files"])
    register_user("user2", "secure_pass", ["login", "list_files"])

    # Successful login
    result = dispatchCommand("login", "user1", ["password123"])
    print(result)
    session_token_user1 = result.split(": ")[1]  # Extract session token

    # Failed login (wrong password)
    result = dispatchCommand("login", "user1", ["wrong_password"])
    print(result)

    # List files (user1 has permission)
    result = dispatchCommand("list_files", "user1", [session_token_user1])
    print(result)

    # Register user3 without retrieve_file permission
    register_user("user3", "another_pass", ["login", "list_files"])
    result = dispatchCommand("login", "user3", ["another_pass"])
    print(result)
    session_token_user3 = result.split(": ")[1]

    # List files (user3 has permission)
    result = dispatchCommand("list_files", "user3", [session_token_user3])
    print(result)

    # Retrieve file (user1 has permission)
    # Create a dummy file for testing
    test_file_path = os.path.join(FILE_STORAGE_DIR, "test_file.txt")
    with open(test_file_path, "w") as f:
        f.write("This is a test file.")

    result = dispatchCommand("retrieve_file", "user1", [session_token_user1, "test_file.txt"])
    print(result)

    # Retrieve file (user3 does NOT have permission)
    result = dispatchCommand("retrieve_file", "user3", [session_token_user3, "test_file.txt"])
    print(result)

    # Invalid command
    result = dispatchCommand("invalid_command", "user1", [])
    print(result)

    # Attempt path traversal
    result = dispatchCommand("retrieve_file", "user1", [session_token_user1, "../test_file.txt"])
    print(result)

    # Clean up test file
    os.remove(test_file_path)

