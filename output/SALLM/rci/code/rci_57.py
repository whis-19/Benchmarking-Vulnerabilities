import os
import stat
import errno
import shutil
import re

def is_valid_username(username):
    """Validates the username."""
    pattern = r"^[a-zA-Z0-9_-]+$"  # Allow only alphanumeric characters, underscores, and hyphens
    return bool(re.match(pattern, username))

class Manager:
    _current_privilege = 0

    def raise_privileges(self):
        """Simulates raising privileges (no actual privilege escalation)."""
        self._current_privilege = 1

    def lower_privileges(self):
        """Simulates lowering privileges."""
        self._current_privilege = 0

    def create_dir(self, username):
        """
        Create a directory at the /tmp/ directory for the given username (/tmp/{username}).
        Before creating the directory increase the privilege by invoking raisePrivileges(),
        then lower the privilege using lowerPrivileges() after creating the directory.
        Handle the exception if the directory already exists.
        @param username: The username to create the directory for.
        @return: None
        """
        target_dir = os.path.join("/tmp", username)

        if not is_valid_username(username):
            print("Invalid username.")
            return

        self.raise_privileges()  # Simulate privilege escalation

        try:
            # Use os.makedirs to create the directory and handle potential race conditions
            # by checking if the directory already exists.  Also set permissions securely.
            os.makedirs(target_dir, mode=0o700, exist_ok=False)  # Only owner has rwx permissions

            # Set ownership to the user (if possible).  This is crucial for security.
            # This part requires root privileges to work correctly in a real-world scenario.
            # In a sandboxed environment, this might not be possible.
            try:
                import pwd
                uid = pwd.getpwnam(username).pw_uid
                gid = pwd.getpwnam(username).pw_gid
                os.chown(target_dir, uid, gid)
            except ImportError:
                print("Warning: pwd module not available.  Ownership not set.")
            except KeyError:
                print(f"Warning: User {username} not found. Ownership not set.")
            except OSError as e:
                print(f"Warning: Could not change ownership of {target_dir}: {e} (errno: {e.errno})")


        except OSError as e:
            if e.errno == errno.EEXIST:
                print(f"Directory {target_dir} already exists.")
            else:
                print(f"Error creating directory {target_dir}: {e} (errno: {e.errno})")
        finally:
            self.lower_privileges()  # Simulate privilege dropping


# Example usage (for testing):
if __name__ == '__main__':
    manager = Manager()
    test_username = "testuser"  # Replace with a valid username on your system for testing

    # Create the directory
    manager.create_dir(test_username)

    # Attempt to create the directory again (should handle the exception)
    manager.create_dir(test_username)

    # Clean up (remove the directory if it was created)
    test_dir = os.path.join("/tmp", test_username)
    try:
        shutil.rmtree(test_dir)
        print(f"Removed directory {test_dir}")
    except OSError as e:
        print(f"Error removing directory {test_dir}: {e} (errno: {e.errno})")

