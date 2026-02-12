import os
import stat
import logging
import re
import unicodedata  # For Unicode normalization
import resource  # For resource limits

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Manager:

    def __init__(self, base_dir="/var/app_data", max_username_length=32, allowed_username_chars=r"^[a-zA-Z0-9_]+$", reserved_usernames=None, default_file_permissions=0o600):
        """
        Initializes the Manager with configurable settings.
        """
        self.base_dir = base_dir
        self.max_username_length = max_username_length
        self.allowed_username_chars = allowed_username_chars
        self.reserved_usernames = reserved_usernames if reserved_usernames is not None else set()  # Default to empty set
        self.default_file_permissions = default_file_permissions

    def create_dir(self, username):
        """
        Creates a directory for the given username.
        Validates and sanitizes the username to prevent path traversal.
        Sets appropriate file permissions.

        @param username: The username to create the directory for.
        @return: None
        """
        # Validate and sanitize username to prevent path traversal
        if not self._is_valid_username(username):
            logging.error(f"Invalid username: {username}.  Aborting directory creation.")
            return

        target_dir = os.path.join(self.base_dir, username)

        # Prevent path traversal attacks
        if not os.path.abspath(target_dir).startswith(os.path.abspath(self.base_dir)):
            logging.error(f"Path traversal attempt detected.  Aborting directory creation for username: {username}")
            return

        try:
            # Create the directory with restrictive permissions (700 - owner only)
            os.makedirs(target_dir, mode=0o700, exist_ok=False)  # exist_ok=False to prevent overwriting existing directories silently
            # Set owner to the current user (optional, but good practice)
            # This requires the script to be run with sufficient privileges (e.g., root)
            try:
                uid = os.geteuid()  # Get the user ID of the current process
                gid = os.getegid()  # Get the group ID of the current process
                os.chown(target_dir, uid, gid)
            except OSError as e:
                logging.error(f"Failed to change ownership of directory {target_dir}: {e}") # Changed to error
                raise # Re-raise the exception to prevent proceeding without ownership change

            logging.info(f"Directory created successfully: {target_dir}")
            self._log_audit_event(f"Directory created for user: {username}", "success") # Auditing

        except FileExistsError:
            logging.warning(f"Directory already exists: {target_dir}")
            self._log_audit_event(f"Directory creation failed for user: {username} (directory exists)", "failure") # Auditing
            return # Or raise an exception, depending on the desired behavior
        except OSError as e:
            logging.error(f"Error creating directory {target_dir}: {e}")
            self._log_audit_event(f"Directory creation failed for user: {username} (OSError: {e})", "failure") # Auditing
            # Add more specific error handling here if needed
            if e.errno == 13:  # Permission denied
                logging.error("Permission denied while creating directory.  Check file system permissions.")
            return # Or raise an exception, depending on the desired behavior

    def create_file(self, username, filename, content):
        """
        Creates a file within the user's directory with restrictive permissions.
        """
        if not self._is_valid_username(username):
            logging.error(f"Invalid username: {username}.  Aborting file creation.")
            return

        user_dir = os.path.join(self.base_dir, username)
        filepath = os.path.join(user_dir, filename)

        # Ensure the file is within the user's directory (prevent path traversal)
        if not os.path.abspath(filepath).startswith(os.path.abspath(user_dir)):
            logging.error(f"Path traversal attempt detected. Aborting file creation for username: {username}, filename: {filename}")
            return

        try:
            # Set umask to restrict default file permissions
            old_umask = os.umask(0o077)  # Ensure files are not world-readable or world-writable
            try:
                with open(filepath, "w") as f:
                    f.write(content)
                # Restore the original umask
            finally:
                os.umask(old_umask)

            # Set specific file permissions (e.g., owner-only read/write)
            os.chmod(filepath, self.default_file_permissions)
            logging.info(f"File created successfully: {filepath}")
            self._log_audit_event(f"File created for user: {username}, filename: {filename}", "success") # Auditing

        except OSError as e:
            logging.error(f"Error creating file {filepath}: {e}")
            self._log_audit_event(f"File creation failed for user: {username}, filename: {filename} (OSError: {e})", "failure") # Auditing

    def _is_valid_username(self, username):
        """
        Validates the username to prevent path traversal and other security issues.
        This is a crucial security measure.

        @param username: The username to validate.
        @return: True if the username is valid, False otherwise.
        """
        # Check for empty username
        if not username:
            logging.warning("Username cannot be empty.")
            return False

        # Normalize the username for consistent validation (e.g., lowercase, Unicode normalization)
        username = username.lower()  # Example: Convert to lowercase
        username = unicodedata.normalize('NFKC', username)  # Example: Unicode normalization

        # Check for path traversal characters
        if ".." in username or "/" in username or "\\" in username:
            logging.warning("Username contains invalid characters (.., /, \\).")
            return False

        # Check for excessively long usernames (prevent buffer overflows, etc.)
        if len(username) > self.max_username_length:
            logging.warning("Username is too long.")
            return False

        # Check if the username starts with a hyphen (can cause issues with command-line tools)
        if username.startswith("-"):
            logging.warning("Username cannot start with a hyphen (-).")
            return False

        # Check if the username is in the reserved usernames list
        if username in self.reserved_usernames:
            logging.warning(f"Username '{username}' is reserved and cannot be used.")
            return False

        # Add more checks as needed, e.g., regular expression for allowed characters
        # Example:  Allow only alphanumeric characters and underscores
        if not re.match(self.allowed_username_chars, username):
            logging.warning("Username contains invalid characters. Only alphanumeric and underscores are allowed.")
            return False

        return True

    def _log_audit_event(self, message, status):
        """
        Logs an audit event.  This could be extended to write to a dedicated audit log.
        """
        logging.info(f"AUDIT: {status.upper()} - {message}")

    def set_resource_limits(self, cpu_time_limit=10, memory_limit=1024 * 1024 * 100):  # Example limits (10 seconds CPU, 100MB memory)
        """
        Sets resource limits for the current process.  Requires elevated privileges.
        """
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_time_limit, cpu_time_limit))  # CPU time limit (seconds)
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))  # Memory limit (bytes)
            logging.info("Resource limits set successfully.")
        except OSError as e:
            logging.error(f"Failed to set resource limits: {e}.  Requires elevated privileges.")

    def drop_privileges(self, uid=1000, gid=1000):  # Example: Drop to user with UID 1000, GID 1000
        """
        Drops privileges to a less privileged user.  Requires elevated privileges.
        """
        if os.geteuid() != 0:
            logging.warning("Not running as root.  Cannot drop privileges.")
            return

        try:
            os.setgid(gid)
            os.setuid(uid)
            logging.info(f"Dropped privileges to UID: {uid}, GID: {gid}")
        except OSError as e:
            logging.error(f"Failed to drop privileges: {e}")

# Example Usage (for testing purposes)
if __name__ == '__main__':
    # Configure the Manager with custom settings
    manager = Manager(
        base_dir="/opt/app_data",  # Example custom base directory
        max_username_length=20,
        allowed_username_chars=r"^[a-z0-9]+$",  # Only lowercase alphanumeric
        reserved_usernames={"admin", "root", "administrator"},
        default_file_permissions=0o600
    )

    # Test resource limits (requires root)
    # manager.set_resource_limits()

    # Test dropping privileges (requires root)
    # manager.drop_privileges()

    # Test with a valid username
    manager.create_dir("testuser")
    manager.create_file("testuser", "my_file.txt", "This is some content.")

    # Test with an invalid username (path traversal attempt)
    manager.create_dir("../testuser")

    # Test with another valid username
    manager.create_dir("another_user")

    # Test with an empty username
    manager.create_dir("")

    # Test with a username containing invalid characters
    manager.create_dir("user/with/slash")

    # Test with a long username
    manager.create_dir("this_is_a_very_long_username_that_exceeds_the_maximum_length")

    # Test with a username starting with a hyphen
    manager.create_dir("-invaliduser")

    # Test with a reserved username
    manager.create_dir("admin")

