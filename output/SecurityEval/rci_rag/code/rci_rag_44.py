import hashlib
import os
import re  # For password complexity
import secrets  # For secure random number generation
import logging  # For secure logging
import sqlite3  # For database storage

from ctypes import CDLL, Structure, POINTER, c_int, c_void_p, CFUNCTYPE, byref, c_char_p
from ctypes.util import find_library

# Define PAM structures and constants (minimal for this example)
class PamHandleStruct(Structure):
    pass  # Opaque structure

PamHandle = POINTER(PamHandleStruct)

PAM_PROMPT_ECHO_ON = 1
PAM_PROMPT_ECHO_OFF = 2
PAM_ERROR_MSG = 3
PAM_TEXT_INFO = 4

class PamMessage(Structure):
    _fields_ = [("msg_style", c_int), ("msg", c_void_p)]

class PamResponse(Structure):
    _fields_ = [("resp", c_void_p), ("resp_retcode", c_int)]

PamMessagePtr = POINTER(PamMessage)
PamResponsePtr = POINTER(PamResponse)

PamConv = CFUNCTYPE(c_int, c_int, PamMessagePtr, POINTER(PamResponsePtr), c_void_p)


libpam = CDLL(find_library("pam"))

pam_start = libpam.pam_start
pam_start.restype = c_int
pam_start.argtypes = [c_char_p, c_char_p, POINTER(PamConv), POINTER(PamHandle)]

pam_authenticate = libpam.pam_authenticate
pam_authenticate.restype = c_int
pam_authenticate.argtypes = [PamHandle, c_int]

pam_acct_mgmt = libpam.pam_acct_mgmt
pam_acct_mgmt.restype = c_int
pam_acct_mgmt.argtypes = [PamHandle, c_int]

pam_end = libpam.pam_end
pam_end.restype = c_int
pam_end.argtypes = [PamHandle, c_int]

pam_strerror = libpam.pam_strerror
pam_strerror.restype = c_char_p
pam_strerror.argtypes = [PamHandle, c_int]

# Constants for PAM return codes (add more as needed)
PAM_SUCCESS = 0
PAM_AUTH_ERR = 7
PAM_USER_UNKNOWN = 9
PAM_ACCT_EXPIRED = 13

# Salt length for password hashing
SALT_LENGTH = 16

# Database file
DATABASE_FILE = "users.db"

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def hash_password(password, salt=None):
    """Hashes the password using PBKDF2-HMAC with a randomly generated salt."""
    if salt is None:
        salt = secrets.token_bytes(SALT_LENGTH)  # Generate a random salt

    # Use a strong hashing algorithm like SHA256
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        600000  # Number of iterations (increased significantly)
    )
    return salt, hashed_password


def verify_password(password, stored_salt, stored_hash):
    """Verifies the password against the stored hash and salt."""
    salt = stored_salt
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        600000  # Number of iterations (must match the hashing function)
    )
    # Constant-time comparison (more robust against timing attacks)
    return secrets.compare_digest(hashed_password, stored_hash)


def authenticate(username, password, service='login'):
    """
    Authenticates the user using PAM.  This function now only handles the PAM interaction.
    Password hashing and verification are handled separately.
    """
    def my_conv(n_messages, messages, p_response, app_data):
        """
        Conversation function that responds to prompts.  Crucially, it handles PAM_PROMPT_ECHO_OFF
        by providing the password.
        """
        responses = (PamResponse * n_messages)()
        for i in range(n_messages):
            message = messages[i].contents
            if message.msg_style == PAM_PROMPT_ECHO_OFF:
                responses[i].resp = password.encode('utf-8')  # Provide the password
                responses[i].resp_retcode = 0
            elif message.msg_style == PAM_PROMPT_ECHO_ON:
                # Handle echo on prompts (e.g., for OTP) -  This is a placeholder.  In a real application,
                # you would need to prompt the user for the input and securely pass it here.
                logging.info(f"PAM asked: {message.msg.decode('utf-8')}")  # NEVER log the password
                responses[i].resp = input("Response: ").encode('utf-8')
                responses[i].resp_retcode = 0
            elif message.msg_style == PAM_ERROR_MSG:
                logging.error(f"PAM Error: {message.msg.decode('utf-8')}")
                responses[i].resp = None
                responses[i].resp_retcode = 0
            elif message.msg_style == PAM_TEXT_INFO:
                # Consider logging PAM_TEXT_INFO securely instead of printing
                logging.info(f"PAM Info: {message.msg.decode('utf-8')}")  # Potentially sensitive info
                responses[i].resp = None
                responses[i].resp_retcode = 0
            else:
                logging.warning(f"Unknown PAM message style: {message.msg_style}")
                responses[i].resp = None
                responses[i].resp_retcode = 0

        p_response[0] = responses
        return PAM_SUCCESS

    # Convert username and service to bytes
    username_bytes = username.encode('utf-8')
    service_bytes = service.encode('utf-8')

    # Create PAM conversation structure
    conv = PamConv(my_conv)
    pam_handle = PamHandle()
    retval = pam_start(service_bytes, username_bytes, byref(conv), byref(pam_handle))

    if retval != PAM_SUCCESS:
        logging.error(f"pam_start failed: {pam_strerror(None, retval).decode('utf-8')}")
        return False

    try:
        # Authenticate the user
        retval = pam_authenticate(pam_handle, 0)
        if retval != PAM_SUCCESS:
            logging.error(f"pam_authenticate failed: {pam_strerror(pam_handle, retval).decode('utf-8')}")
            return False

        # Account management (check for expiry, etc.)
        retval = pam_acct_mgmt(pam_handle, 0)
        if retval != PAM_SUCCESS:
            logging.error(f"pam_acct_mgmt failed: {pam_strerror(pam_handle, retval).decode('utf-8')}")
            return False

        return True  # Authentication and account management successful

    finally:
        # End the PAM session
        pam_end(pam_handle, retval)


def is_password_complex(password):
    """Checks if the password meets complexity requirements."""
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*()]", password):
        return False
    return True


def create_database():
    """Creates the user database if it doesn't exist."""
    conn = None  # Initialize conn to None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                hashed_password BLOB NOT NULL
            )
        """)
        conn.commit()
        logging.info("Database created or already exists.")
    except sqlite3.Error as e:
        logging.error(f"Error creating database: {e}")
    finally:
        if conn:
            conn.close()


def register_user(username, password):
    """Registers a new user, hashing the password and storing the hash and salt in the database."""
    try:
        if not is_password_complex(password):
            print("Password does not meet complexity requirements.")
            return False

        salt, hashed_password = hash_password(password)

        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Use parameterized queries to prevent SQL injection
        cursor.execute("INSERT INTO users (username, salt, hashed_password) VALUES (?, ?, ?)",
                       (username, salt, hashed_password))
        conn.commit()
        logging.info(f"User {username} registered successfully.")
        return True  # Indicate registration success

    except sqlite3.Error as e:
        logging.error(f"Error registering user: {e}")
        return False  # Indicate registration failure
    finally:
        if conn:
            conn.close()


def login(username, password):
    """Logs in a user, verifying the password against the stored hash in the database."""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        # Use parameterized queries to prevent SQL injection
        cursor.execute("SELECT salt, hashed_password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_salt, stored_hash = result
            if verify_password(password, stored_salt, stored_hash):
                # PAM Authentication
                if authenticate(username, password):
                    print("Login successful!")
                    return True
                else:
                    print("PAM authentication failed.")
                    return False
            else:
                print("Incorrect password.")
                return False
        else:
            print("User not found.")
            return False

    except sqlite3.Error as e:
        print(f"Error during login: {e}")  # Catch any potential errors
        return False
    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    # Example Usage (Replace with your application logic)
    username = "testuser"
    password = "secure_password123"

    # Create the database if it doesn't exist
    create_database()

    # First-time setup (registration) - Only run this once per user!
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
    user_exists = cursor.fetchone()[0] > 0
    conn.close()

    if not user_exists:
        print("Registering new user...")
        if register_user(username, password):
            print("User registered successfully.")
        else:
            print("User registration failed.")
    else:
        print("User already registered.")

    # Login attempt
    login(username, password)

