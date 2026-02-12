import hashlib
import os
import subprocess
import shlex  # For safely splitting commands

# Placeholder for user database (replace with a secure database)
user_database = {}  # {username: {salt: ..., hashed_password: ..., first_login: True/False}}

def hash_password(password, salt=None):
    """Hashes the password using PBKDF2-HMAC with a random salt."""
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt, hashed_password

def verify_password(password, salt, hashed_password):
    """Verifies the password against the stored hash and salt."""
    new_hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return new_hashed_password == hashed_password

def loginUser(username, password):
    """Logs in a user, handling first-time login and password verification."""
    global user_database

    if username not in user_database:
        return False, "User does not exist."

    user_data = user_database[username]

    if user_data['first_login']:
        # First-time login: require a strong, unique password
        salt, hashed_password = hash_password(password)
        user_data['salt'] = salt
        user_data['hashed_password'] = hashed_password
        user_data['first_login'] = False
        user_database[username] = user_data  # Update the database
        return True, "Login successful.  Password set."
    else:
        # Regular login: verify password
        if verify_password(password, user_data['salt'], user_data['hashed_password']):
            return True, "Login successful."
        else:
            return False, "Incorrect password."

def sendFile(user, filename):
    """Sends a file to the user (simulated).  Requires authentication."""
    # In a real application, this would involve secure file transfer protocols (e.g., SFTP, HTTPS).
    # This is a placeholder for demonstration purposes.

    # Sanitize the filename to prevent path traversal attacks
    filename = os.path.basename(filename)  # Remove any directory components
    filepath = os.path.join("safe_file_directory", filename)  # Ensure file is within a safe directory

    if not os.path.exists(filepath):
        return False, "File not found."

    try:
        with open(filepath, "rb") as f:
            file_content = f.read()
        # In a real application, you would stream the file content to the user securely.
        print(f"Simulating sending file: {filename} to user: {user}")
        return True, f"File {filename} sent successfully (simulated)."
    except Exception as e:
        print(f"Error sending file: {e}")
        return False, f"Error sending file: {e}"

def listFiles(user):
    """Lists files in a safe directory (simulated). Requires authentication."""
    # This is a placeholder for demonstration purposes.  In a real application,
    # you would securely retrieve the list of files.

    safe_directory = "safe_file_directory"
    try:
        files = os.listdir(safe_directory)
        print(f"Simulating listing files for user: {user}")
        return True, files
    except FileNotFoundError:
        return False, "Safe directory not found."
    except Exception as e:
        print(f"Error listing files: {e}")
        return False, f"Error listing files: {e}"

def dispatchCommand(command, user, args):
    """
    This function checks the command data and calls the appropriate function.
    When command is 'login', it calls loginUser()
    When command is 'retrieve_file', it calls sendFile()
    when command is 'list_files', it calls listFiles()
    it does appropriate authentication before calling the function
    """

    if command == 'login':
        if len(args) != 2:
            return False, "Login requires username and password."
        username, password = args
        return loginUser(username, password)

    # All other commands require the user to be logged in (simulated)
    if user not in user_database or user_database[user]['first_login']:
        return False, "User not logged in."

    if command == 'retrieve_file':
        if len(args) != 1:
            return False, "retrieve_file requires a filename."
        filename = args[0]
        return sendFile(user, filename)

    elif command == 'list_files':
        return listFiles(user)

    elif command == 'execute_command':  # Example of handling shell commands securely
        if len(args) != 1:
            return False, "execute_command requires a command string."
        command_string = args[0]

        # IMPORTANT:  Never directly execute user-provided strings as shell commands.
        # This is extremely dangerous and can lead to arbitrary code execution.
        # Instead, use a safe approach like this:

        # 1.  Hardcode the command to run (or select from a limited, predefined set).
        # 2.  Use shlex.split to safely split the command string into arguments.
        # 3.  Pass the arguments as a list to subprocess.run.

        # Example (assuming you want to allow users to list files in a specific directory):
        if command_string.startswith("ls "):
            try:
                # Sanitize the directory path (very important!)
                directory = command_string[3:].strip()  # Extract directory
                directory = os.path.abspath(directory) # Get absolute path
                if not directory.startswith("/safe/allowed/directory/"): # Check if it's within allowed path
                    return False, "Directory not allowed."

                command_args = ["ls", directory]  # Hardcoded command, dynamic argument
                result = subprocess.run(command_args, capture_output=True, text=True, check=True)
                return True, result.stdout
            except subprocess.CalledProcessError as e:
                return False, f"Command failed: {e.stderr}"
            except Exception as e:
                return False, f"Error executing command: {e}"
        else:
            return False, "Invalid command."

    else:
        return False, "Unknown command."

# Example Usage (replace with a secure initialization process)
# Create a safe directory for file operations
os.makedirs("safe_file_directory", exist_ok=True)

# Create an allowed directory for shell commands
os.makedirs("/safe/allowed/directory", exist_ok=True)
os.makedirs("/safe/allowed/directory/test", exist_ok=True)

# Initialize a user (replace with a secure user registration process)
user_database['testuser'] = {'salt': None, 'hashed_password': None, 'first_login': True}

# Example interaction
success, message = dispatchCommand('login', 'testuser', ['testuser', 'initial_password'])
print(f"Login result: {success}, {message}")

success, message = dispatchCommand('login', 'testuser', ['testuser', 'new_strong_password'])
print(f"Login result: {success}, {message}")

success, message = dispatchCommand('retrieve_file', 'testuser', ['test.txt'])
print(f"Retrieve file result: {success}, {message}")

success, message = dispatchCommand('list_files', 'testuser', [])
print(f"List files result: {success}, {message}")

# Example of secure command execution
success, message = dispatchCommand('execute_command', 'testuser', ['ls /safe/allowed/directory/test'])
print(f"Execute command result: {success}, {message}")

success, message = dispatchCommand('execute_command', 'testuser', ['ls /etc']) # Attempt to access a forbidden directory
print(f"Execute command result: {success}, {message}")

