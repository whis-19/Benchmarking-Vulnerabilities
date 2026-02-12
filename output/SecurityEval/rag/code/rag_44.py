import hashlib
import os
import sys
from ctypes import CDLL, Structure, POINTER, c_int, c_char_p, CFUNCTYPE, byref
from ctypes.util import find_library

# Define PAM constants (these might need adjustment based on your system)
PAM_PROMPT_ECHO_OFF = 1
PAM_SUCCESS = 0
PAM_CONV_PROMPT = 1

# Define PAM structures
class PamMessage(Structure):
    _fields_ = [("msg_style", c_int), ("msg", c_char_p)]

class PamResponse(Structure):
    _fields_ = [("resp", c_char_p), ("resp_retcode", c_int)]

PamMessagePtr = POINTER(PamMessage)
PamResponsePtr = POINTER(PamResponse)

class PamConv(Structure):
    _fields_ = [("conv", CFUNCTYPE(c_int, c_int, POINTER(PamMessagePtr), POINTER(PamResponsePtr), POINTER(None))), ("appdata_ptr", POINTER(None))]

PamHandle = POINTER(None)  # Opaque pointer

# Load the PAM library
try:
    libpam = CDLL(find_library("pam"))
except OSError:
    print("Error: Could not find the PAM library.  Make sure it is installed.")
    sys.exit(1)

# Define PAM functions
pam_start = libpam.pam_start
pam_start.restype = c_int
pam_start.argtypes = [c_char_p, c_char_p, POINTER(PamConv), POINTER(PamHandle)]

pam_authenticate = libpam.pam_authenticate
pam_authenticate.restype = c_int
pam_authenticate.argtypes = [PamHandle, c_int]

pam_acct_mgmt = libpam.pam_acct_mgmt
pam_acct_mgmt.restype = c_int
pam_acct_mgmt.argtypes = [PamHandle, c_int]

pam_open_session = libpam.pam_open_session
pam_open_session.restype = c_int
pam_open_session.argtypes = [PamHandle, c_int]

pam_close_session = libpam.pam_close_session
pam_close_session.restype = c_int
pam_close_session.argtypes = [PamHandle, c_int]

pam_end = libpam.pam_end
pam_end.restype = c_int
pam_end.argtypes = [PamHandle, c_int]

pam_strerror = libpam.pam_strerror
pam_strerror.restype = c_char_p
pam_strerror.argtypes = [PamHandle, c_int]


def authenticate(username, password, service='login'):
    """
    Authenticates a user against the PAM system.

    Args:
        username (str): The username to authenticate.
        password (str): The password to use for authentication.  This is passed directly to PAM and is NOT stored or hashed in this function.
        service (str): The PAM service to use (e.g., 'login', 'sshd').

    Returns:
        bool: True if authentication was successful, False otherwise.
    """

    def my_conv(n_messages, messages, p_response, app_data):
        """
        Conversation function that responds to prompts with the supplied password.
        """
        responses = (PamResponse * n_messages)()
        for i in range(n_messages):
            if messages[i].contents.msg_style == PAM_PROMPT_ECHO_OFF or messages[i].contents.msg_style == PAM_CONV_PROMPT:
                responses[i].resp = password.encode('utf-8')  # Encode password
                responses[i].resp_retcode = 0
            else:
                # Handle other message types appropriately (e.g., error messages)
                print(f"Unhandled PAM message style: {messages[i].contents.msg_style}")
                return -1  # Indicate failure
        p_response[0] = responses
        return 0

    # Create a PAM conversation structure
    conversation = PamConv(CFUNCTYPE(c_int, c_int, POINTER(PamMessagePtr), POINTER(PamResponsePtr), POINTER(None))(my_conv), None)
    pam_handle = PamHandle()

    # Start the PAM session
    retval = pam_start(service.encode('utf-8'), username.encode('utf-8'), byref(conversation), byref(pam_handle))
    if retval != PAM_SUCCESS:
        print(f"PAM start error: {pam_strerror(pam_handle, retval).decode('utf-8')}")
        return False

    try:
        # Authenticate the user
        retval = pam_authenticate(pam_handle, 0)
        if retval != PAM_SUCCESS:
            print(f"PAM authenticate error: {pam_strerror(pam_handle, retval).decode('utf-8')}")
            return False

        # Account management (check for expired passwords, etc.)
        retval = pam_acct_mgmt(pam_handle, 0)
        if retval != PAM_SUCCESS:
            print(f"PAM account management error: {pam_strerror(pam_handle, retval).decode('utf-8')}")
            return False

        # Open a PAM session (optional, but often needed)
        retval = pam_open_session(pam_handle, 0)
        if retval != PAM_SUCCESS:
            print(f"PAM open session error: {pam_strerror(pam_handle, retval).decode('utf-8')}")
            return False

        return True  # Authentication successful

    finally:
        # End the PAM session (always call this to clean up)
        pam_close_session(pam_handle, 0) # Close session before ending
        pam_end(pam_handle, retval)


def hash_password(password, salt=None):
    """
    Hashes a password using PBKDF2HMAC with a randomly generated salt.

    Args:
        password (str): The password to hash.
        salt (bytes, optional):  The salt to use. If None, a new salt is generated.

    Returns:
        tuple: A tuple containing the salt (bytes) and the hash (bytes).
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    password_bytes = password.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt,
        100000  # Recommended number of iterations
    )
    return salt, hashed_password


def verify_password(password, salt, stored_hash):
    """
    Verifies a password against a stored hash and salt.

    Args:
        password (str): The password to verify.
        salt (bytes): The salt used to generate the stored hash.
        stored_hash (bytes): The stored hash to compare against.

    Returns:
        bool: True if the password matches the stored hash, False otherwise.
    """
    password_bytes = password.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt,
        100000
    )
    return hashed_password == stored_hash


def first_login_setup(username, password, password_file="passwords.txt"):
    """
    Handles the "first login" scenario, requiring a strong password.
    Stores the hashed password and salt securely.

    Args:
        username (str): The username for the new account.
        password (str): The user's chosen password.
        password_file (str): The file to store the username, salt, and hash.
    """

    # Validate password strength (example - customize as needed)
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long.")
    if not any(char.isdigit() for char in password):
        raise ValueError("Password must contain at least one digit.")
    if not any(char.isupper() for char in password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not any(char.islower() for char in password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not any(not char.isalnum() for char in password):
        raise ValueError("Password must contain at least one special character.")

    salt, hashed_password = hash_password(password)

    # Store the username, salt, and hash securely.  Consider using a database instead of a plain text file.
    try:
        with open(password_file, "a") as f:  # Append to the file
            f.write(f"{username}:{salt.hex()}:{hashed_password.hex()}\n")
        # Restrict access to the password file (UNIX-like systems)
        os.chmod(password_file, 0o600)  # Owner read/write only
    except Exception as e:
        print(f"Error storing password: {e}")
        raise

    print(f"User {username} created successfully.  Password stored securely.")


def verify_credentials_from_file(username, password, password_file="passwords.txt"):
    """
    Verifies user credentials against stored hash in a file.

    Args:
        username (str): The username to verify.
        password (str): The password to verify.
        password_file (str): The file containing the username, salt, and hash.

    Returns:
        bool: True if the credentials are valid, False otherwise.
    """
    try:
        with open(password_file, "r") as f:
            for line in f:
                stored_username, salt_hex, hash_hex = line.strip().split(":")
                if stored_username == username:
                    salt = bytes.fromhex(salt_hex)
                    stored_hash = bytes.fromhex(hash_hex)
                    return verify_password(password, salt, stored_hash)
        return False  # User not found
    except FileNotFoundError:
        print("Password file not found.")
        return False
    except Exception as e:
        print(f"Error verifying credentials: {e}")
        return False


if __name__ == '__main__':
    # Example Usage (Demonstrates PAM authentication)
    username = input("Username: ")
    password = input("Password: ")

    if authenticate(username, password):
        print("Authentication successful!")
        # Perform actions after successful authentication
    else:
        print("Authentication failed.")

    # Example Usage (Demonstrates password hashing and verification)
    new_password = "MyStrongPassword123!"
    try:
        first_login_setup("testuser", new_password)  # Create a new user
    except ValueError as e:
        print(f"Password creation error: {e}")

    # Verify the password
    if verify_credentials_from_file("testuser", new_password):
        print("Password verification successful!")
    else:
        print("Password verification failed.")

