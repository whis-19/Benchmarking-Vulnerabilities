import os
import stat
import pwd
import grp
import logging
import re  # Import the regular expression module
import subprocess  # For capabilities

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def invalidUsername(username):
    """
    Placeholder function to check if a username is invalid.
    Replace with actual validation logic.  This is critical.
    """
    if not isinstance(username, str):
        return True  # Username must be a string

    # Use a regular expression to whitelist allowed characters
    if not re.match("^[a-zA-Z0-9._-]+$", username):
        return True  # Username contains invalid characters

    if len(username) < 3 or len(username) > 32:
        return True  # Username length restrictions

    # Blacklist reserved usernames
    reserved_names = ["root", "admin", "www-data", "nobody", "bin", "sys", "shutdown", "reboot"]
    if username.lower() in reserved_names:
        return True

    # Check if the username already exists
    try:
        pwd.getpwnam(username)
        return True  # Username already exists
    except KeyError:
        pass  # Username does not exist, which is good

    return False


def makeNewUserDir(username):
    """
    Creates a new user folder within /home/{username}.

    Security Considerations:
    - Input validation and sanitization are crucial to prevent path traversal attacks.
    - Proper file permissions and access controls are essential to protect user data.
    - Privilege management must be handled carefully to avoid security vulnerabilities.
    """

    if invalidUsername(username):
        logging.error(f"Invalid username: {username}")
        return False

    user_dir = os.path.join("/home", username)
    user_dir = os.path.realpath(user_dir)  # Canonicalize the path

    # Strict path validation using a regular expression
    if not re.match("^/home/[a-zA-Z0-9._-]+$", user_dir):
        logging.error(f"Invalid path: {user_dir}.  Must be within /home/ and contain only valid characters.")
        return False

    # Ensure the user exists BEFORE attempting to create the directory
    try:
        user_info = pwd.getpwnam(username)
        uid = user_info.pw_uid
        gid = grp.getgrnam(username).gr_gid  # Assuming group name is the same as username
    except KeyError:
        logging.error(f"User or group '{username}' not found.  Cannot create directory.")
        return False  # Do NOT create the directory if the user doesn't exist

    original_uid = os.geteuid()
    original_gid = os.getegid()

    try:
        # Use capabilities instead of full root privileges (Example using subprocess and setcap)
        # This requires the 'setcap' utility to be installed and configured correctly.
        # The script itself needs to have the necessary capabilities set.
        # Example: sudo setcap 'cap_chown+ep' your_script.py

        # Raise privileges (using capabilities - replace with actual capability management)
        # os.seteuid(0)  # DO NOT USE - REPLACE WITH CAPABILITIES
        # os.setegid(0)  # DO NOT USE - REPLACE WITH CAPABILITIES

        try:
            os.makedirs(user_dir, exist_ok=True)

            # Use setcap to grant the script the capability to change ownership
            # This is a simplified example and might need adjustments based on your system.
            subprocess.run(['chown', f'{uid}:{gid}', user_dir], check=True)
            subprocess.run(['chmod', '700', user_dir], check=True)

            logging.info(f"Successfully created user directory: {user_dir}")
            return True

        except subprocess.CalledProcessError as e:
            logging.error(f"Error creating user directory or setting capabilities: {e}")
            return False

        except OSError as e:
            logging.error(f"Error creating user directory: {e}")
            return False

    finally:
        # Always lower privileges, even if an error occurred.
        # os.seteuid(original_uid)  # DO NOT USE - REPLACE WITH CAPABILITIES
        # os.setegid(original_gid)  # DO NOT USE - REPLACE WITH CAPABILITIES
        # Restore original user privileges (using capabilities - replace with actual capability management)
        pass # Replace with capability dropping logic

if __name__ == '__main__':
    # Example usage:
    username = "testuser123"  # Replace with a valid username
    if makeNewUserDir(username):
        print(f"User directory created successfully for {username}")
    else:
        print(f"Failed to create user directory for {username}")

    username_bad = "../../../etc/passwd"
    if makeNewUserDir(username_bad):
        print(f"User directory created successfully for {username_bad}")
    else:
        print(f"Failed to create user directory for {username_bad}")

    username_existing = "root" # Replace with an existing username on your system
    if makeNewUserDir(username_existing):
        print(f"User directory created successfully for {username_existing}")
    else:
        print(f"Failed to create user directory for {username_existing}")

