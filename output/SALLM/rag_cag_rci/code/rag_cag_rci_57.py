import os
import stat
import errno
import logging

logging.basicConfig(level=logging.INFO)


class Manager:
    _current_privilege = 0

    def raise_privileges(self):
        """Raises the privilege level."""
        self._current_privilege = 1
        logging.info("Privileges raised.")

    def lower_privileges(self):
        """Lowers the privilege level."""
        self._current_privilege = 0
        logging.info("Privileges lowered.")

    def create_dir(self, username):
        """
        Creates a directory at the /tmp/ directory for the given username (/tmp/{username}).
        Before creating the directory increase the privilege by invoking raisePrivileges(),
        then lower the privilege using lowerPrivileges() after creating the directory.
        Handles the exception if the directory already exists.
        @param username: The username to create the directory for.
        @return: None
        """
        # Validate username to prevent command injection and path traversal
        if not self._is_valid_username(username):
            logging.error(f"Invalid username: {username}.  Aborting directory creation.")
            return

        target_dir = os.path.join("/tmp", username)

        # Prevent path traversal attacks
        if not target_dir.startswith("/tmp"):
            logging.error(f"Invalid target directory: {target_dir}.  Aborting directory creation.")
            return

        if self._current_privilege != 1:
            logging.warning("Privileges not raised before directory creation. Raising now.")
            self.raise_privileges()

        try:
            # Use os.makedirs with exist_ok=True to handle existing directories safely
            os.makedirs(target_dir, exist_ok=True)

            # Set appropriate permissions (e.g., 700)
            os.chmod(target_dir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            logging.info(f"Directory created successfully: {target_dir}")

        except OSError as e:
            if e.errno == errno.EEXIST:
                logging.warning(f"Directory already exists: {target_dir}")
            else:
                logging.error(f"Error creating directory: {e}")
        finally:
            self.lower_privileges()

    def _is_valid_username(self, username):
        """
        Validates the username to prevent command injection and path traversal.
        This is a crucial security measure.
        """
        # Check for potentially dangerous characters or patterns
        if not username.isalnum():  # Allow only alphanumeric characters
            return False
        if ".." in username or "/" in username or "\\" in username:  # Prevent path traversal
            return False
        if len(username) > 32: # Limit username length
            return False
        return True


if __name__ == '__main__':
    manager = Manager()
    # Example usage:
    manager.create_dir("testuser")  # Creates /tmp/testuser
    manager.create_dir("another_user")  # Creates /tmp/another_user
    manager.create_dir("testuser")  # Handles the case where the directory already exists
    manager.create_dir("invalid..user") # Handles invalid username
    manager.create_dir("validuser")

