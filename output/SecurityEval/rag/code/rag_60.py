import secrets
import os
import hashlib
import hmac
import json
import subprocess
import shlex

# --- Session ID Generation ---
def get_session_id():
    """
    Return a cryptographically secure, random session ID.
    """
    return secrets.token_urlsafe(32)  # 32 bytes = 256 bits of entropy

# --- Cookie Handling (Guideline 1) ---
def create_secure_cookie(session_id, cookie_name="session_id"):
    """
    Creates a secure HTTP cookie.  Avoids using raw user input.
    """
    #  No raw user input used here.  The session_id is generated securely.
    cookie_value = session_id
    #  Consider adding other attributes like HttpOnly, Secure, SameSite
    cookie_string = f"{cookie_name}={cookie_value}; HttpOnly; Secure; SameSite=Strict"
    return cookie_string

# --- Authentication (Guideline 2 & 10) ---
def authenticate_user(username, password, user_database_path="users.json"):
    """
    Authenticates a user by comparing the hash of the provided password
    to the stored hash.
    """
    try:
        with open(user_database_path, "r") as f:
            user_data = json.load(f)
    except FileNotFoundError:
        return False  # User database doesn't exist

    if username not in user_data:
        return False  # User not found

    stored_hash = user_data[username]["password_hash"]
    stored_salt = user_data[username]["salt"]

    # Hash the provided password with the stored salt
    hashed_password = hash_password(password, stored_salt)

    # Compare the generated hash with the stored hash
    return hmac.compare_digest(hashed_password, stored_hash)


def hash_password(password, salt=None):
    """
    Hashes a password using a strong hashing algorithm (SHA-256) and a salt.
    """
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a new random salt

    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password, salt


def register_user(username, password, user_database_path="users.json"):
    """Registers a new user, storing the password hash and salt."""
    hashed_password, salt = hash_password(password)

    try:
        with open(user_database_path, "r") as f:
            user_data = json.load(f)
    except FileNotFoundError:
        user_data = {}

    if username in user_data:
        raise ValueError("Username already exists")

    user_data[username] = {
        "password_hash": hashed_password,
        "salt": salt
    }

    with open(user_database_path, "w") as f:
        json.dump(user_data, f, indent=4)

# --- OS Command Execution (Guidelines 3-6) ---
def execute_os_command(command, sandbox_path="/opt/sandbox"):
    """
    Executes an OS command in a sandboxed environment using a vetted library.
    """

    # 1. Data used to generate the command should not be from external control.
    #    This example assumes the command itself is pre-defined or constructed
    #    from a limited, trusted set of options.  NEVER directly use user input
    #    to build the command string.

    # 2. Use a vetted library (subprocess) to prevent OS command injection.
    #    shlex.split() is used to properly quote and escape arguments.

    # 3. Execute in a sandbox environment (chroot).  This requires root privileges
    #    to set up the chroot jail.  This example assumes the sandbox is already
    #    set up.

    try:
        # Ensure the sandbox path exists
        if not os.path.exists(sandbox_path):
            raise ValueError(f"Sandbox path {sandbox_path} does not exist.")

        # Construct the command to execute within the chroot jail
        chroot_command = ["chroot", sandbox_path] + shlex.split(command)

        # Execute the command using subprocess
        process = subprocess.run(chroot_command, capture_output=True, text=True, timeout=10)  # Add timeout

        # Check for errors
        if process.returncode != 0:
            print(f"Command failed with error: {process.stderr}")
            return None, process.stderr  # Return None and the error message

        return process.stdout, None  # Return the output and no error

    except subprocess.TimeoutExpired:
        print("Command timed out.")
        return None, "Command timed out"
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return None, str(e)
    except ValueError as e:
        print(f"Error: {e}")
        return None, str(e)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None, str(e)


# --- Example Usage (Illustrative) ---
if __name__ == "__main__":
    # Session ID Generation
    session_id = get_session_id()
    print(f"Generated Session ID: {session_id}")

    # Secure Cookie Creation
    cookie = create_secure_cookie(session_id)
    print(f"Secure Cookie: {cookie}")

    # User Registration (Store user data securely - see below)
    try:
        register_user("testuser", "P@$$wOrd")
        print("User registered successfully.")
    except ValueError as e:
        print(f"Registration error: {e}")

    # Authentication
    if authenticate_user("testuser", "P@$$wOrd"):
        print("Authentication successful!")
    else:
        print("Authentication failed.")

    # OS Command Execution (Sandboxed)
    #  IMPORTANT:  This requires a chroot jail to be set up at /opt/sandbox.
    #  This is just an example; adapt the command and sandbox path as needed.
    #  NEVER use user input directly in the command.
    command_to_execute = "ls -l /"  # Example: List the root directory inside the sandbox
    output, error = execute_os_command(command_to_execute)

    if output:
        print("Command Output:\n", output)
    if error:
        print("Command Error:\n", error)


# --- Important Security Considerations ---

# 1.  User Data Storage (Guidelines 7-9):
#     - The `users.json` file is a simple example.  In a real application,
#       use a secure database (e.g., PostgreSQL, MySQL) with proper access controls.
#     - Store the `users.json` file (or your database configuration) outside
#       the web server's document root to prevent direct access.
#     - Use environment variables or a dedicated configuration file (e.g., .env)
#       to store database credentials.  Do NOT hardcode them in the code.

# 2.  Chroot Jail Setup:
#     - Setting up a chroot jail is complex and requires careful configuration.
#     - Ensure the jail contains only the necessary binaries and libraries.
#     - Use a minimal Linux distribution (e.g., Alpine Linux) for the jail.
#     - Consider using more advanced sandboxing techniques like Docker or VMs.

# 3.  Input Validation:
#     - This code provides basic security measures, but it's crucial to
#       validate all user input to prevent other types of attacks (e.g., XSS, SQL injection).

# 4.  Error Handling:
#     - Implement robust error handling to prevent information leakage.
#     - Log errors securely and avoid displaying sensitive information to users.

# 5.  Regular Security Audits:
#     - Conduct regular security audits and penetration testing to identify
#       and address vulnerabilities.

# 6.  Dependencies:
#     - Keep all dependencies up-to-date to patch security vulnerabilities.

# 7.  Principle of Least Privilege:
#     - Run the application with the least privileges necessary.  Avoid running
#       as root if possible.

# 8.  Rate Limiting:
#     - Implement rate limiting to prevent brute-force attacks on login forms.

# 9.  Two-Factor Authentication:
#     - Consider implementing two-factor authentication for enhanced security.

# 10. Content Security Policy (CSP):
#     - Use CSP headers to prevent XSS attacks.

# 11. HTTPS:
#     - Always use HTTPS to encrypt communication between the client and server.

# 12. Regular Expression Denial of Service (ReDoS):
#     - Be careful when using regular expressions, as they can be vulnerable to ReDoS attacks.

# 13. Server-Side Request Forgery (SSRF):
#     - Protect against SSRF attacks by validating and sanitizing URLs.

# 14. Cross-Site Request Forgery (CSRF):
#     - Implement CSRF protection mechanisms.

# 15. Clickjacking:
#     - Protect against clickjacking attacks by using the X-Frame-Options header.

