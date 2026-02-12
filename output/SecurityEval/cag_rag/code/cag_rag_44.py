import ctypes
import ctypes.util
import os
import sys
import logging

# Configure logging (important for security auditing)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- PAM interaction ---
try:
    libpam = ctypes.CDLL(ctypes.util.find_library("pam"))
except OSError as e:
    logging.error(f"Failed to load libpam: {e}")
    raise  # Re-raise the exception to halt execution if PAM is essential

    
# Define PAM constants (use enums for clarity and type safety)
class PamConst(object):
    PAM_PROMPT_ECHO_OFF = 1
    PAM_PROMPT_ECHO_ON = 2
    PAM_ERROR_MSG = 3
    PAM_TEXT_INFO = 4

class PamReturnCode(object):
    PAM_SUCCESS = 0
    PAM_AUTH_ERR = 7
    PAM_USER_UNKNOWN = 9
    PAM_MAXTRIES = 10
    PAM_PERM_DENIED = 12
    PAM_AUTHINFO_UNAVAIL = 5
    PAM_CRED_INSUFFICIENT = 11
    PAM_ACCT_EXPIRED = 13
    PAM_SESSION_ERR = 14
    PAM_AUTHTOK_ERR = 15
    PAM_CONV_ERR = 16
    PAM_AUTHTOK_RECOVERY_ERR = 17
    PAM_AUTHTOK_LOCK_BUSY = 18
    PAM_AUTHTOK_DISABLE_AGING = 19
    PAM_TRY_AGAIN = 20
    PAM_IGNORE = 21
    PAM_ABORT = 22
    PAM_SYMBOL_ERR = 23
    PAM_SERVICE_ERR = 24
    PAM_SYSTEM_ERR = 25
    PAM_BUF_ERR = 26
    PAM_OPEN_ERR = 27
    PAM_MAX = 28

# Define PAM structures and function signatures
PamHandle = ctypes.c_void_p
PamMessage = ctypes.Structure
PamResponse = ctypes.Structure

PamMessage._fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]
PamResponse._fields_ = [("resp", ctypes.c_char_p), ("resp_retcode", ctypes.c_int)]

PamMessagePtr = ctypes.POINTER(PamMessage)
PamResponsePtr = ctypes.POINTER(PamResponse)

PamConversation = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_int,
    ctypes.POINTER(PamMessagePtr),
    ctypes.POINTER(PamResponsePtr),
    ctypes.c_void_p,
)

pam_start = libpam.pam_start
pam_start.restype = ctypes.c_int
pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(PamConversation), ctypes.POINTER(PamHandle)]

pam_authenticate = libpam.pam_authenticate
pam_authenticate.restype = ctypes.c_int
pam_authenticate.argtypes = [PamHandle, ctypes.c_int]

pam_acct_mgmt = libpam.pam_acct_mgmt
pam_acct_mgmt.restype = ctypes.c_int
pam_acct_mgmt.argtypes = [PamHandle, ctypes.c_int]

pam_end = libpam.pam_end
pam_end.restype = ctypes.c_int
pam_end.argtypes = [PamHandle, ctypes.c_int]

pam_strerror = libpam.pam_strerror
pam_strerror.restype = ctypes.c_char_p
pam_strerror.argtypes = [PamHandle, ctypes.c_int]

def authenticate(username, password, service='login'):
    """
    Authenticates a user against the PAM stack.

    Args:
        username (str): The username to authenticate.
        password (str): The password to use for authentication.
        service (str): The PAM service to use (default: 'login').

    Returns:
        bool: True if authentication succeeds, False otherwise.
    """

    def my_conv(n_messages, messages, p_response, app_data):
        """
        Conversation function that responds to prompts.  Handles PAM_PROMPT_ECHO_OFF with the provided password.
        """
        responses = (PamResponse * n_messages)()
        for i in range(n_messages):
            message = messages[i].contents
            if message.msg_style == PamConst.PAM_PROMPT_ECHO_OFF:
                responses[i].resp = password.encode('utf-8')  # Encode password
                responses[i].resp_retcode = 0
            elif message.msg_style == PamConst.PAM_PROMPT_ECHO_ON:
                # Handle echo on prompts (e.g., for OTP).  For security, consider logging these.
                logging.warning("PAM requested echo-on prompt.  This is unusual and may indicate a security issue.")
                responses[i].resp = b"" # Or handle appropriately if your PAM config expects input
                responses[i].resp_retcode = 0
            elif message.msg_style == PamConst.PAM_ERROR_MSG:
                logging.error(f"PAM Error: {message.msg.decode('utf-8')}") # Decode error message
                responses[i].resp = b""
                responses[i].resp_retcode = 0
            elif message.msg_style == PamConst.PAM_TEXT_INFO:
                logging.info(f"PAM Info: {message.msg.decode('utf-8')}") # Decode info message
                responses[i].resp = b""
                responses[i].resp_retcode = 0
            else:
                logging.error(f"Unknown PAM message style: {message.msg_style}")
                responses[i].resp = b""
                responses[i].resp_retcode = 0

        p_response[0] = responses
        return 0

    conversation = PamConversation(my_conv)
    handle = PamHandle()
    retval = pam_start(service.encode('utf-8'), username.encode('utf-8'), conversation, ctypes.byref(handle)) # Encode username and service

    if retval != PamReturnCode.PAM_SUCCESS:
        logging.error(f"pam_start failed: {pam_strerror(None, retval).decode('utf-8')}") # Decode error message
        return False

    try:
        retval = pam_authenticate(handle, 0)
        if retval == PamReturnCode.PAM_SUCCESS:
            # Account management (e.g., check for expired accounts)
            retval = pam_acct_mgmt(handle, 0)
            if retval == PamReturnCode.PAM_SUCCESS:
                logging.info(f"Authentication successful for user: {username}")
                return True
            else:
                logging.warning(f"Account management failed: {pam_strerror(handle, retval).decode('utf-8')}") # Decode error message
                return False
        else:
            logging.warning(f"Authentication failed: {pam_strerror(handle, retval).decode('utf-8')}") # Decode error message
            return False
    finally:
        # Always clean up the PAM handle
        pam_end(handle, retval)


# Example usage (for testing only - REMOVE IN PRODUCTION)
if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python pam_auth.py <username> <password>")
        sys.exit(1)

    username = sys.argv[1]
    password = sys.argv[2]

    if authenticate(username, password):
        print("Authentication successful!")
    else:
        print("Authentication failed.")

