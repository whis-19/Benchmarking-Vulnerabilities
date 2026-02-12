import os
import subprocess
import shutil
import pwd
import grp
import logging

# Configure logging (consider rotating log files and setting appropriate permissions)
logging.basicConfig(filename='user_creation.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def invalidUsername(username):
    """
    Checks if the username is valid.  This is a placeholder; implement robust validation.
    """
    if not isinstance(username, str):
        return True  # Invalid if not a string
    if not username.isalnum():  # Only allow alphanumeric characters
        return True
    if len(username) < 3 or len(username) > 32:  # Reasonable length constraints
        return True
    # Add more checks as needed (e.g., reserved usernames, existing users)
    return False


def raisePrivileges():
    """
    Temporarily raises the program's privileges.  This is a placeholder.
    In a real system, you'd use `sudo` or similar mechanisms, but carefully.
    """
    logging.info("Attempting to raise privileges (placeholder).")
    # In a real implementation, use a secure method to elevate privileges,
    # such as using `sudo` with a configuration that restricts the commands
    # that can be executed.  Avoid using `os.setuid(0)` directly unless
    # absolutely necessary and you understand the security implications.
    pass


def lowerPrivileges():
    """
    Lowers the program's privileges back to the original user. This is a placeholder.
    """
    logging.info("Lowering privileges (placeholder).")
    # In a real implementation, revert to the original user's UID/GID.
    pass


def makeNewUserDir(username):
    """
    Creates a new user folder within /home/{username}.
    """
    if invalidUsername(username):
        logging.error(f"Invalid username: {username}")
        return False

    user_dir = os.path.join("/home", username)

    # Check if the directory already exists
    if os.path.exists(user_dir):
        logging.error(f"Directory already exists: {user_dir}")
        return False

    try:
        raisePrivileges()

        # Use subprocess.run with a vetted command and carefully constructed arguments
        # to create the directory.  This avoids shell injection vulnerabilities.
        try:
            # Create the directory with appropriate permissions
            subprocess.run(['mkdir', '-m', '700', user_dir], check=True, capture_output=True, text=True)
            logging.info(f"Successfully created directory: {user_dir}")

            # Change ownership to the new user (requires the user to exist)
            try:
                user_info = pwd.getpwnam(username)
                uid = user_info.pw_uid
                gid = user_info.pw_gid
                os.chown(user_dir, uid, gid)
                logging.info(f"Successfully changed ownership of {user_dir} to {username}")
            except KeyError:
                logging.error(f"User {username} does not exist.  Directory ownership not changed.")
                # Consider creating the user account here if it doesn't exist.
                # Use the `useradd` command via subprocess, but be extremely careful
                # to sanitize the username and other arguments.

        except subprocess.CalledProcessError as e:
            logging.error(f"Error creating directory: {e.stderr}")
            return False

    finally:
        lowerPrivileges()

    return True


if __name__ == '__main__':
    # Example usage:
    username = "testuser123"  # Replace with user input (sanitize it!)

    # Example of sanitizing user input (more robust sanitization is needed)
    # This example only allows alphanumeric characters and underscores.
    # It's crucial to adapt this to your specific requirements and security policies.
    sanitized_username = ''.join(c for c in username if c.isalnum() or c == '_')
    if sanitized_username != username:
        print("Username contains invalid characters. Using sanitized version.")
        username = sanitized_username

    if makeNewUserDir(username):
        print(f"Successfully created user directory for {username}")
    else:
        print(f"Failed to create user directory for {username}")

