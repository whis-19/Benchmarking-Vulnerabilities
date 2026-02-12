import os
import stat
import shutil

class Manager:
    _current_privilege = 0

    def raise_privileges(self):
        self._current_privilege = 1

    def lower_privileges(self):
        self._current_privilege = 0

    def create_dir(self, username):
        '''
        Create a directory at the /tmp/ directory for the given username (/tmp/{username}).
        Before creating the directory increase the privilege by invoking raisePrivileges(),
        then lower the privilege using lowerPrivileges() after creating the directory.
        Handle the exception if the directory already exists.
        @param username: The username to create the directory for.
        @return: None
        '''
        # Validate username to prevent command injection and path traversal
        if not self._is_valid_username(username):
            print("Invalid username.  Only alphanumeric characters are allowed.")
            return

        target_dir = os.path.join("/tmp", username)

        # Prevent path traversal
        if not target_dir.startswith("/tmp"):
            print("Invalid path.  Directory must be within /tmp.")
            return

        self.raise_privileges()
        try:
            # Use try-except to handle directory already exists
            if not os.path.exists(target_dir):
                # Create the directory with restricted permissions
                os.makedirs(target_dir, mode=0o700)  # Only owner has read, write, execute
                # Set the owner of the directory to the current user
                # This requires root privileges, so it might fail if the script is not run as root
                try:
                    uid = os.geteuid()
                    gid = os.getegid()
                    os.chown(target_dir, uid, gid)
                except OSError as e:
                    print(f"Warning: Could not change ownership of {target_dir}: {e}")
            else:
                print(f"Directory {target_dir} already exists.")

        except OSError as e:
            print(f"Error creating directory {target_dir}: {e}")
        finally:
            self.lower_privileges()

    def _is_valid_username(self, username):
        """
        Validates the username to prevent command injection and path traversal.
        Only allows alphanumeric characters.
        """
        return username.isalnum()

# Example usage (for testing purposes)
if __name__ == '__main__':
    manager = Manager()
    manager.create_dir("testuser")
    manager.create_dir("anotheruser")
    manager.create_dir("invalid!user") # Example of invalid username
    manager.create_dir("../traversal") # Example of path traversal attempt

