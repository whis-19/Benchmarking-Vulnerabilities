import ctypes
from ctypes import CDLL, Structure, POINTER, c_int, c_char_p, c_void_p
import os
import logging
import sys
import re
import msvcrt  # For Windows password input

# Configure logging (replace with your desired configuration)
logging.basicConfig(
    filename="auth.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Define PAM constants (common values, adjust if needed for your system)
PAM_SUCCESS = 0
PAM_AUTH_ERR = 7
PAM_USER_PROMPT = 1
PAM_PROMPT_ECHO_OFF = 1
PAM_PROMPT_ECHO_ON = 2
PAM_ERROR_MSG = 3
PAM_TEXT_INFO = 4

# Define PAM structures
class PamMessage(Structure):
    _fields_ = [("msg_style", c_int), ("msg", c_char_p)]


class PamResponse(Structure):
    _fields_ = [("resp", c_char_p), ("resp_retcode", c_int)]


PamMessagePtr = POINTER(PamMessage)
PamResponsePtr = POINTER(PamResponse)

# Define the conversation function type
PamConvFunc = ctypes.CFUNCTYPE(
    c_int,
    c_int,
    POINTER(PamMessagePtr),
    POINTER(POINTER(PamResponse)),
    c_void_p,
)


class PamHandleStruct(Structure):
    pass  # Opaque structure, definition not needed in Python


PamHandle = POINTER(PamHandleStruct)


# Load the PAM library
PAM_LIBRARY_PATH = os.environ.get("PAM_LIBRARY_PATH", "/lib64/libpam.so.0")  # Example

try:
    libpam = CDLL(PAM_LIBRARY_PATH)
except OSError as e:
    logging.error(f"Error: Could not find the PAM library at {PAM_LIBRARY_PATH}: {e}")
    print(
        "Error: Could not find the PAM library.  Make sure it is installed and the PAM_LIBRARY_PATH environment variable is set correctly. See auth.log for details."
    )
    sys.exit(1)  # Exit the program if PAM library is not found


# Define PAM functions
pam_start = libpam.pam_start
pam_start.restype = c_int
pam_start.argtypes = [c_char_p, c_char_p, POINTER(PamConvFunc), POINTER(PamHandle)]

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


def authenticate(username, password, service="login"):
    """
    Authenticates a user against PAM.

    Args:
        username (str): The username to authenticate.
        password (str): The password to use for authentication.
        service (str): The PAM service to use (default: 'login').

    Returns:
        bool: True if authentication was successful, False otherwise.
    """

    auth_ret = PAM_SUCCESS  # Store the authentication return code
    acct_ret = PAM_SUCCESS  # Store the account management return code

    def my_conv(n_messages, messages, p_response, app_data):
        """
        Conversation function that responds to prompts with the supplied password.
        """
        nonlocal auth_ret, acct_ret  # Access the outer scope variables
        responses = (PamResponse * n_messages)()
        for i in range(n_messages):
            msg_style = messages[i].contents.msg_style
            msg = messages[i].contents.msg

            if msg_style == PAM_PROMPT_ECHO_OFF or msg_style == PAM_PROMPT_ECHO_ON:
                # Encode password to bytes immediately before use
                password_bytes = password.encode("utf-8")
                responses[i].resp = password_bytes
                responses[i].resp_retcode = 0
                # Attempt to zero the password in memory (not foolproof)
                # This is the best we can do in Python, but it's not perfect.
                # Overwrite the local variable.  This doesn't guarantee immediate memory clearing.
                # del password_bytes # Deleting the variable doesn't guarantee immediate memory release
                # password = "" # Overwriting the original password variable is dangerous.
            elif msg_style == PAM_ERROR_MSG or msg_style == PAM_TEXT_INFO:
                if msg:
                    message = msg.decode("utf-8", errors="ignore")  # Handle decoding errors
                    logging.info(f"PAM Message: {message}")
                    print(f"PAM Message: {message}")  # Also print to console for important messages
                responses[i].resp = None
                responses[i].resp_retcode = 0
            else:
                logging.error(f"Unexpected PAM message style: {msg_style}")
                print("Authentication failed. See auth.log for details.")
                auth_ret = PAM_AUTH_ERR  # Set an error code
                return -1  # Indicate an error

        p_response[0] = responses
        return PAM_SUCCESS

    # Input validation
    if not (4 <= len(username) <= 32 and re.match("^[a-zA-Z0-9._-]+$", username)):
        logging.warning(f"Invalid username format: {username}")
        print("Invalid username format. See auth.log for details.")
        return False

    # Validate service name (example)
    allowed_services = ["login", "sudo", "my_app"]  # Whitelist
    if service not in allowed_services:
        logging.warning(f"Invalid service name: {service}")
        print("Invalid service name. See auth.log for details.")
        return False

    if len(password) > 128 or len(password) < 8:  # Limit password length
        logging.warning(f"Password length invalid for user: {username}")
        print("Authentication failed. See auth.log for details.")
        return False

    # Convert username and service to bytes
    username_bytes = username.encode("utf-8")
    service_bytes = service.encode("utf-8")

    # Create a PAM handle
    pam_handle = PamHandle()
    conv = PamConvFunc(my_conv)
    ret = pam_start(service_bytes, username_bytes, conv, ctypes.byref(pam_handle))

    if ret != PAM_SUCCESS:
        error_message = pam_strerror(None, ret)
        if error_message:
            error_message = error_message.decode("utf-8", errors="ignore")
            logging.error(f"PAM start failed: {error_message}")
        else:
            logging.error("PAM start failed: Unknown error.")
        print("Authentication failed. See auth.log for details.")
        return False

    try:
        # Authenticate the user
        ret = pam_authenticate(pam_handle, 0)
        auth_ret = ret  # Store the authentication return code
        if ret != PAM_SUCCESS:
            error_message = pam_strerror(pam_handle, ret)
            if error_message:
                error_message = error_message.decode("utf-8", errors="ignore")
                logging.warning(f"PAM authentication failed: {error_message}")
            else:
                logging.warning("PAM authentication failed: Unknown error.")
            print("Authentication failed. See auth.log for details.")
            return False

        # Account management (optional, but recommended)
        ret = pam_acct_mgmt(pam_handle, 0)
        acct_ret = ret  # Store the account management return code
        if ret != PAM_SUCCESS:
            error_message = pam_strerror(pam_handle, ret)
            if error_message:
                error_message = error_message.decode("utf-8", errors="ignore")
                logging.warning(f"PAM account management failed: {error_message}")
            else:
                logging.warning("PAM account management failed: Unknown error.")
            print("Authentication failed. See auth.log for details.")
            return False

        return True

    finally:
        # End the PAM session
        ret = pam_end(pam_handle, ret)  # Pass the last return code to pam_end
        if ret != PAM_SUCCESS:
            error_message = pam_strerror(None, ret)
            if error_message:
                error_message = error_message.decode("utf-8", errors="ignore")
                logging.error(f"PAM end failed: {error_message}")
            else:
                logging.error("PAM end failed: Unknown error.")

        # Log the original authentication/account management error (if any)
        if auth_ret != PAM_SUCCESS:
            logging.error(f"Authentication failed with code: {auth_ret}")
        if acct_ret != PAM_SUCCESS:
            logging.error(f"Account management failed with code: {acct_ret}")


# Example usage (replace with your actual username and password)
if __name__ == "__main__":
    username = input("Username: ")  # Get username from user

    # Get password securely (Windows only)
    if os.name == 'nt':
        password = msvcrt.getpass("Password: ".encode()).decode()
    else:
        import getpass
        password = getpass.getpass("Password: ")

    if authenticate(username, password):
        print("Authentication successful!")
    else:
        print("Authentication failed.")

