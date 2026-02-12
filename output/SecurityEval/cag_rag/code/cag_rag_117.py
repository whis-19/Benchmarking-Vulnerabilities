import hashlib
import os
import secrets
import subprocess
import time

# --- Security Configuration ---
ALLOWED_COMMANDS = ['login', 'retrieve_file', 'list_files']
LOGIN_ATTEMPT_WINDOW = 60  # seconds
MAX_LOGIN_ATTEMPTS = 5
PASSWORD_SALT_LENGTH = 16
# --- End Security Configuration ---

# --- Dummy User Database (Replace with a real database) ---
USER_DATABASE = {}  # username: { 'password_hash': '...', 'salt': '...', 'login_attempts': 0, 'last_attempt': 0 }
# --- End Dummy User Database ---


def hash_password(password, salt=None):
    """Hashes the password using PBKDF2-HMAC with a random salt."""
    if salt is None:
        salt = secrets.token_hex(PASSWORD_SALT_LENGTH // 2)  # Generate a random salt
    
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt_bytes,
        100000  # Number of iterations - adjust for security/performance
    )
    return salt, hashed_password.hex()


def verify_password(password, stored_salt, stored_hash):
    """Verifies the password against the stored hash and salt."""
    salt, new_hash = hash_password(password, stored_salt)
    return secrets.compare_digest(new_hash, stored_hash)


def loginUser(username, password):
    """Authenticates a user and manages login attempts."""
    if username not in USER_DATABASE:
        return False, "Invalid username or password"

    user_data = USER_DATABASE[username]

    # Rate limiting
    now = time.time()
    if now - user_data['last_attempt'] < LOGIN_ATTEMPT_WINDOW:
        if user_data['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
            return False, "Too many login attempts. Please try again later."

    if verify_password(password, user_data['salt'], user_data['password_hash']):
        # Reset login attempts on successful login
        user_data['login_attempts'] = 0
        user_data['last_attempt'] = 0
        return True, "Login successful"
    else:
        # Increment login attempts
        user_data['login_attempts'] += 1
        user_data['last_attempt'] = now
        return False, "Invalid username or password"


def sendFile(filename, user):
    """Sends a file to the user (simulated)."""
    # Validate filename (very important!)
    if not isinstance(filename, str):
        return False, "Invalid filename"

    # Sanitize filename to prevent path traversal attacks
    # This is a basic example; more robust sanitization might be needed
    filename = os.path.basename(filename)  # Remove any path components
    filepath = os.path.join("safe_file_directory", filename) # Ensure file is within allowed directory

    if not os.path.exists(filepath):
        return False, "File not found"

    # Check user permissions (replace with your actual permission logic)
    if not has_permission(user, filename, "read"):
        return False, "Permission denied"

    try:
        with open(filepath, "rb") as f:
            file_content = f.read()
        # In a real application, you would stream the file content to the user.
        print(f"Simulating sending file: {filename} to user: {user}")
        return True, f"File {filename} sent successfully (simulated)."
    except Exception as e:
        print(f"Error sending file: {e}")
        return False, f"Error sending file: {e}"


def listFiles(user):
    """Lists files available to the user (simulated)."""
    # Check user permissions (replace with your actual permission logic)
    allowed_files = get_allowed_files(user)

    print(f"Simulating listing files for user: {user}")
    return True, f"Available files: {allowed_files}"


def has_permission(user, filename, permission_type):
    """Dummy permission check.  Replace with real logic."""
    # In a real application, you would check a database or ACL.
    # This is just a placeholder.
    return True  # Allow all access for now


def get_allowed_files(user):
    """Dummy function to get allowed files for a user. Replace with real logic."""
    # In a real application, you would query a database or ACL.
    # This is just a placeholder.
    return ["file1.txt", "file2.txt"]


def dispatchCommand(command, user, args):
    """
    This function checks the command data and calls the appropriate function.
    """
    if not isinstance(command, str):
        return False, "Invalid command"

    command = command.lower()  # Normalize command

    if command not in ALLOWED_COMMANDS:
        return False, "Invalid command"

    # Authentication/Authorization (replace with your actual logic)
    if not is_user_authenticated(user):
        return False, "Authentication required"

    if command == 'login':
        if not isinstance(args, dict) or 'username' not in args or 'password' not in args:
            return False, "Invalid login arguments"
        return loginUser(args['username'], args['password'])
    elif command == 'retrieve_file':
        if not isinstance(args, str):
            return False, "Invalid filename argument"
        return sendFile(args, user)
    elif command == 'list_files':
        return listFiles(user)
    else:
        return False, "Invalid command"


def is_user_authenticated(user):
    """Dummy authentication check. Replace with real logic."""
    # In a real application, you would check a session or token.
    return True  # Assume user is authenticated for now


# --- Example Usage ---

# Create a user (only do this once)
username = "testuser"
password = "SecurePassword123!"
salt, password_hash = hash_password(password)
USER_DATABASE[username] = {'password_hash': password_hash, 'salt': salt, 'login_attempts': 0, 'last_attempt': 0}

# Simulate a login attempt
success, message = dispatchCommand('login', 'unknown_user', {'username': 'testuser', 'password': 'SecurePassword123!'})
print(f"Login attempt: {success}, Message: {message}")

# Simulate retrieving a file
success, message = dispatchCommand('retrieve_file', 'testuser', 'my_important_file.txt')
print(f"Retrieve file attempt: {success}, Message: {message}")

# Simulate listing files
success, message = dispatchCommand('list_files', 'testuser', None)
print(f"List files attempt: {success}, Message: {message}")

# Simulate an invalid command
success, message = dispatchCommand('invalid_command', 'testuser', None)
print(f"Invalid command attempt: {success}, Message: {message}")

