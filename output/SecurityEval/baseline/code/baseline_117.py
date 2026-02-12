import os
import hashlib
import secrets
import logging

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Dummy user database (replace with a secure database in a real application)
USER_DATABASE = {
    "user1": {
        "hashed_password": hashlib.sha256("password123".encode()).hexdigest(),  # Store hashed passwords!
        "salt": "random_salt_1", # Store salts!
        "permissions": ["login", "retrieve_file", "list_files"]
    },
    "user2": {
        "hashed_password": hashlib.sha256("secure_pass".encode()).hexdigest(),
        "salt": "another_salt",
        "permissions": ["login", "list_files"]
    }
}

# Dummy file storage directory (replace with a secure storage solution)
FILE_STORAGE_DIR = "files"  # Relative path for simplicity; use absolute paths in production

# Ensure the file storage directory exists
os.makedirs(FILE_STORAGE_DIR, exist_ok=True)


def loginUser(username, password):
    """
    Authenticates a user and returns a session token if successful.
    """
    if username in USER_DATABASE:
        user_data = USER_DATABASE[username]
        hashed_password = hashlib.sha256((user_data["salt"] + password).encode()).hexdigest()

        if hashed_password == user_data["hashed_password"]:
            # Generate a secure session token
            session_token = secrets.token_hex(32)  # 32 bytes = 64 hex characters
            logging.info(f"User {username} logged in successfully. Session token generated.")
            return session_token
        else:
            logging.warning(f"Login failed for user {username}: Incorrect password.")
            return None
    else:
        logging.warning(f"Login failed: User {username} not found.")
        return None


def sendFile(username, filename):
    """
    Sends a file to the user (simulated).  Requires authentication and authorization.
    """
    filepath = os.path.join(FILE_STORAGE_DIR, filename)

    if not os.path.exists(filepath):
        logging.error(f"File not found: {filename}")
        return "Error: File not found."

    # Check if the user has permission to retrieve this file (replace with more granular checks)
    if "retrieve_file" not in USER_DATABASE.get(username, {}).get("permissions", []):
        logging.warning(f"User {username} does not have permission to retrieve files.")
        return "Error: Permission denied."

    try:
        with open(filepath, "rb") as f:  # Open in binary mode
            file_content = f.read()
        # In a real application, you would stream the file content to the user.
        # This is a simplified example.
        logging.info(f"File {filename} sent to user {username}.")
        return f"File content: {file_content.decode('utf-8', errors='ignore')}" # Decode for demonstration; handle binary data properly in production
    except Exception as e:
        logging.exception(f"Error sending file {filename} to user {username}: {e}")
        return f"Error: Could not read file: {e}"


def listFiles(username):
    """
    Lists files in the file storage directory. Requires authentication and authorization.
    """
    if "list_files" not in USER_DATABASE.get(username, {}).get("permissions", []):
        logging.warning(f"User {username} does not have permission to list files.")
        return "Error: Permission denied."

    try:
        files = os.listdir(FILE_STORAGE_DIR)
        logging.info(f"Files listed for user {username}.")
        return f"Files: {files}"
    except Exception as e:
        logging.exception(f"Error listing files for user {username}: {e}")
        return f"Error: Could not list files: {e}"


def dispatchCommand(command, user, args):
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
        if len(args) != 1:
            logging.warning("retrieve_file command requires a filename argument.")
            return "Error: retrieve_file requires a filename."
        filename = args[0]
        return sendFile(user, filename)

    elif command == "list_files":
        return listFiles(user)

    else:
        logging.warning(f"Invalid command: {command}")
        return "Error: Invalid command."


if __name__ == '__main__':
    # Example Usage (replace with your actual input mechanism)

    # Successful login
    result = dispatchCommand("login", "user1", ["password123"])
    print(result)

    # Failed login (wrong password)
    result = dispatchCommand("login", "user1", ["wrong_password"])
    print(result)

    # List files (user1 has permission)
    result = dispatchCommand("list_files", "user1", [])
    print(result)

    # List files (user2 has permission)
    result = dispatchCommand("list_files", "user2", [])
    print(result)

    # Retrieve file (user1 has permission)
    # Create a dummy file for testing
    with open(os.path.join(FILE_STORAGE_DIR, "test_file.txt"), "w") as f:
        f.write("This is a test file.")

    result = dispatchCommand("retrieve_file", "user1", ["test_file.txt"])
    print(result)

    # Retrieve file (user2 does NOT have permission)
    result = dispatchCommand("retrieve_file", "user2", ["test_file.txt"])
    print(result)

    # Invalid command
    result = dispatchCommand("invalid_command", "user1", [])
    print(result)

