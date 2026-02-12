import os
import pwd
import grp
import stat
import logging
import subprocess
import re  # For username validation
import errno  # For checking specific OSError codes
import capng  # For capabilities (install with `pip install python-capng`)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
BASE_DIR = "/home"
DEFAULT_PERMISSIONS = stat.S_IRWXU | stat.S_ISGID  # User read/write/execute + setgid

# ******************************************************************************
# WARNING: This code is INSECURE without a proper implementation of the
#          raisePrivileges() and lowerPrivileges() functions.  These functions
#          are placeholders and MUST be replaced with a secure mechanism for
#          privilege escalation and de-escalation.  DO NOT USE THIS CODE IN
#          A PRODUCTION ENVIRONMENT WITHOUT ADDRESSING THIS CRITICAL SECURITY
#          ISSUE.  Consider using capabilities instead of full root access.
#          `setuid` should only be considered as an absolute last resort.
# ******************************************************************************

def raisePrivileges():
    """
    Securely raises privileges using capabilities.  Requires careful configuration.
    This is a placeholder and MUST be implemented securely.

    WARNING: Directly switching to root without proper safeguards is extremely dangerous.
    Consider using capabilities instead of full root access.  `setuid` should only be
    considered as an absolute last resort.

    Example using capabilities (requires setcap on the script):
    sudo setcap 'cap_chown+ep,cap_dac_override+ep' your_script.py  # VERY DANGEROUS - AVOID CAP_DAC_OVERRIDE IF POSSIBLE
    """
    logging.warning("raisePrivileges() called.  This is a placeholder and requires secure implementation.")
    try:
        # Use the LEAST number of capabilities necessary.  CAP_DAC_OVERRIDE is very powerful and should be avoided if possible.
        capng.update(capng.CAPNG_ADD, capng.CAPNG_EFFECTIVE, capng.CAP_CHOWN)  # Only allow changing ownership
        # capng.update(capng.CAPNG_ADD, capng.CAPNG_EFFECTIVE, capng.CAP_DAC_OVERRIDE) # AVOID IF POSSIBLE
        capng.apply()
        logging.info("Privileges raised successfully using capabilities.")
    except Exception as e:
        logging.error(f"Error raising privileges: {e}")
        raise  # Re-raise the exception to be handled by the caller

def lowerPrivileges():
    """
    Securely lowers privileges.  This is a placeholder and MUST be implemented securely.

    WARNING: Failing to properly lower privileges after raising them is a major security risk.
    """
    logging.warning("lowerPrivileges() called.  This is a placeholder and requires secure implementation.")
    try:
        capng.update(capng.CAPNG_DROP, capng.CAPNG_EFFECTIVE, capng.CAP_CHOWN)
        # capng.update(capng.CAPNG_DROP, capng.CAPNG_EFFECTIVE, capng.CAP_DAC_OVERRIDE)
        capng.apply()
        logging.info("Privileges lowered successfully.")
    except Exception as e:
        logging.error(f"Error lowering privileges: {e}")
        raise  # Re-raise the exception

def is_safe_path(path, base_dir=BASE_DIR):
    """
    Validates that the given path is within the allowed base directory and does not contain path traversal vulnerabilities.
    """
    if not path:
        return False

    # Check for path traversal attempts
    if ".." in path:
        logging.warning(f"Path traversal attempt detected: Path traversal attempt: {path}")
        return False

    # Normalize the path to remove redundant separators and resolve symbolic links
    # Canonicalize the path BEFORE any security checks.
    abs_path = os.path.abspath(os.path.normpath(os.path.realpath(path.strip())))
    abs_base_dir = os.path.abspath(os.path.normpath(os.path.realpath(base_dir.strip())))

    # Check if the path is within the allowed base directory
    if not abs_path.startswith(abs_base_dir):
        logging.warning(f"Path is outside the allowed base directory: {path}")
        return False

    return True


def validate_username(username):
    """
    Validates the username to prevent injection attacks.
    """
    if not username:
        return False

    # Whitelist of allowed characters: alphanumeric and underscore
    pattern = r"^[a-zA-Z0-9_]+$"
    if not re.match(pattern, username):
        logging.warning(f"Invalid username format: {username}")
        return False

    if len(username) > 32:  # Example length limit
        logging.warning(f"Username too long: {username}")
        return False

    return True


def sanitize_username(username):
    """
    Sanitizes the username by replacing invalid characters with underscores.
    """
    return re.sub(r"[^a-zA-Z0-9_]", "_", username)


def makeNewUserDir(username):
    """
    Creates a directory at the /home/ directory for the given username.
    """
    logging.info(f"makeNewUserDir called for username: {username}")

    if not validate_username(username):
        print("Error: Invalid username.")
        return

    sanitized_username = sanitize_username(username)  # Sanitize the username
    home_dir = os.path.join(BASE_DIR, sanitized_username)

    # Validate the path
    if not is_safe_path(home_dir):
        logging.error(f"Invalid or unsafe path: {home_dir}")
        print(f"Error: Invalid username or path.  Cannot create directory for {username}.") # User feedback
        return

    try:
        raisePrivileges()  # Attempt to raise privileges

        # Create the directory with appropriate permissions
        try:
            # Be aware of the system's umask, which can affect the actual permissions applied.
            # To ensure the desired permissions, you might need to explicitly set the umask:
            # old_umask = os.umask(0o022)  # Set umask to 022 (common default)
            # try:
            os.makedirs(home_dir, exist_ok=False)  # exist_ok=False to prevent overwriting existing directories
            logging.info(f"Directory created successfully: {home_dir}")
            # finally:
            #     os.umask(old_umask)  # Restore the original umask


            # Set ownership and permissions
            try:
                uid = pwd.getpwnam(sanitized_username).pw_uid
                gid = grp.getgrnam(sanitized_username).gr_gid
                os.chown(home_dir, uid, gid)
                os.chmod(home_dir, DEFAULT_PERMISSIONS)  # User read/write/execute + setgid
                logging.info(f"Ownership and permissions set for {home_dir}")
            except KeyError as e:
                logging.error(f"User or group not found: {e}")
                print(f"Error: User or group not found for {username}.  Directory created, but ownership may be incorrect.") # User feedback
            except OSError as e:
                logging.error(f"Error setting ownership or permissions: {e}")
                print(f"Error: Could not set ownership or permissions for {username}'s directory.  Check system logs.") # User feedback


        except FileExistsError:
            logging.warning(f"Directory already exists: {home_dir}")
            print(f"Error: Directory already exists. Please choose a different username or delete the existing directory.") # User feedback
        except OSError as e:
            logging.error(f"Error creating directory: {e}")
            print(f"Error: Could not create directory for {username}.  Check system logs.") # User feedback

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        print(f"An unexpected error occurred. Check the logs for details.")

    finally:
        try:
            lowerPrivileges()  # Ensure privileges are lowered, even if an error occurs
        except Exception as e:
            logging.error(f"Failed to lower privileges in finally block: {e}")
            # Consider what to do if lowering privileges fails.  This is a critical error.
            print("CRITICAL ERROR: Failed to lower privileges.  Check system logs immediately.")

# Example usage (for testing - replace with appropriate user input validation)
if __name__ == "__main__":
    username = input("Enter username: ")  # Get user input
    makeNewUserDir(username)

