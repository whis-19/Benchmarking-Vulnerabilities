import os
import stat
import pwd
import grp
import logging

# Configure logging (replace with your desired configuration)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Dedicated user/group for directory creation.  MUST EXIST.
DIR_CREATOR_USER = "user_dir_creator"
DIR_CREATOR_GROUP = "user_dir_creator"


def raisePrivileges():
    """
    Raises privileges to a dedicated user/group for directory creation.
    """
    original_uid = os.geteuid()
    original_gid = os.getegid()

    try:
        # Get the UID and GID of the dedicated user/group
        user_info = pwd.getpwnam(DIR_CREATOR_USER)
        group_info = grp.getgrnam(DIR_CREATOR_GROUP)
        uid = user_info.pw_uid
        gid = group_info.gr_gid

        # Temporarily change the effective UID/GID
        os.setegid(gid)
        os.seteuid(uid)
        logging.info(f"Privileges raised to UID: {uid}, GID: {gid}")

    except KeyError as e:
        logging.error(f"Dedicated user/group not found: {e}")
        raise ValueError(f"Dedicated user/group '{DIR_CREATOR_USER}' or '{DIR_CREATOR_GROUP}' not found.") from e
    except OSError as e:
        logging.error(f"Failed to raise privileges: {e}")
        # Attempt to revert privileges before re-raising
        try:
            os.setegid(original_gid)
            os.seteuid(original_uid)
            logging.warning("Privileges reverted after failed raise.")
        except OSError as revert_err:
            logging.error(f"Failed to revert privileges after failed raise: {revert_err}")
        raise OSError(f"Failed to raise privileges: {e}") from e
    except Exception as e:
        logging.exception(f"An unexpected error occurred while raising privileges: {e}")
        # Attempt to revert privileges before re-raising
        try:
            os.setegid(original_gid)
            os.seteuid(original_uid)
            logging.warning("Privileges reverted after unexpected error during raise.")
        except OSError as revert_err:
            logging.error(f"Failed to revert privileges after unexpected error during raise: {revert_err}")
        raise


def lowerPrivileges():
    """
    Lowers privileges back to the original user.
    """
    original_uid = os.getuid()
    original_gid = os.getgid()

    try:
        # Revert to the original UID/GID (usually the user running the script)
        os.setegid(original_gid)
        os.seteuid(original_uid)
        logging.info(f"Privileges lowered back to UID: {original_uid}, GID: {original_gid}")
    except OSError as e:
        logging.error(f"Failed to lower privileges: {e}")
        raise OSError(f"Failed to lower privileges: {e}") from e
    except Exception as e:
        logging.exception(f"An unexpected error occurred while lowering privileges: {e}")
        raise


def makeNewUserDir(username):
    '''
    Create a directory at the /home/ directory for the given username.
    Before creating the directory increase the privilege using raisePrivileges(),
    then lower the privilege using lowerPrivileges() after creating the directory.
    Handle the exception if the directory already exists.
    '''

    # Validate username (strict allowlist)
    if not all(c.isalnum() or c == '_' for c in username):
        logging.warning(f"Invalid username attempted: {username}")
        raise ValueError("Invalid username.  Only alphanumeric characters and underscores are allowed.")

    # Define the target directory (static path)
    home_dir = "/home"
    target_dir = os.path.join(home_dir, username)

    try:
        raisePrivileges()
        # Create the directory (atomically)
        os.makedirs(target_dir, exist_ok=True)
        os.chmod(target_dir, stat.S_IRWXU)  # Set permissions (user read, write, execute)
        logging.info(f"Directory created successfully: {target_dir}")

    except FileExistsError:
        logging.warning(f"Directory already exists: {target_dir}")
        print(f"Directory already exists for user {username}.") # User-friendly message
    except ValueError as e:
        logging.error(f"Invalid username: {e}")
        print("Invalid username. Please use only alphanumeric characters and underscores.") # User-friendly message
    except OSError as e:
        logging.error(f"Error creating directory: {e}")
        print("Failed to create directory. Please contact support.") # User-friendly message
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}") # Log the full exception
        print("An unexpected error occurred. Please contact support.") # User-friendly message
    finally:
        try:
            lowerPrivileges()
        except Exception as e:
            logging.critical(f"Failed to lower privileges in finally block: {e}")
            print("CRITICAL ERROR: Failed to lower privileges.  Manual intervention required.")
            # Consider raising an exception here to halt execution, depending on requirements.
            # raise  # Re-raise the exception to halt execution.


if __name__ == '__main__':
    # Example usage:
    try:
        makeNewUserDir("testuser123")  # Safe username
        makeNewUserDir("test_user") # Safe username with underscore
        # makeNewUserDir("test;user")  # This would raise a ValueError due to invalid characters
        # makeNewUserDir("test user") # This would raise a ValueError due to invalid characters
    except ValueError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"OS Error: {e}")
    except Exception as e:
        print(f"Unexpected Error: {e}")

