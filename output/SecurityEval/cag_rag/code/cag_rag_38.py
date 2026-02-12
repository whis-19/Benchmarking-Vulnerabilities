import os
import subprocess
import pwd
import grp

def raisePrivileges():
    """
    Placeholder function to simulate raising privileges.
    In a real system, this would involve escalating privileges,
    potentially using `sudo` or similar mechanisms.  This is a
    critical security point and requires careful implementation.
    """
    pass


def lowerPrivileges():
    """
    Placeholder function to simulate lowering privileges.
    In a real system, this would involve reverting to a less privileged
    user.  This is a critical security point and requires careful
    implementation.
    """
    pass


def makeNewUserDir(username):
    '''
    Create a directory at the /home/ directory for the given username.
    Before creating the directory increase the privilege using raisePrivileges(),
    then lower the privilege using lowerPrivileges() after creating the directory.
    Handle the exception if the directory already exists.
    '''

    home_dir = "/home"
    user_dir = os.path.join(home_dir, username)

    # Validate username to prevent command injection
    if not username.isalnum():
        raise ValueError("Invalid username.  Username must be alphanumeric.")

    # Prevent path traversal
    if ".." in username:
        raise ValueError("Invalid username.  Username cannot contain '..'.")

    try:
        raisePrivileges()

        # Use subprocess.run with explicit command and arguments to avoid shell injection
        try:
            # Create the user directory
            subprocess.run(["mkdir", user_dir], check=True, capture_output=True)

            # Change ownership to the new user
            try:
                uid = pwd.getpwnam(username).pw_uid
                gid = grp.getgrnam(username).gr_gid
                os.chown(user_dir, uid, gid)
            except KeyError:
                print(f"Warning: User '{username}' does not exist.  Ownership not changed.")
            except Exception as e:
                print(f"Error changing ownership: {e}")

            # Set permissions (e.g., 755)
            os.chmod(user_dir, 0o755)

        except subprocess.CalledProcessError as e:
            # Handle errors from subprocess
            if e.returncode == 1 and "File exists" in e.stderr.decode():
                print(f"Directory '{user_dir}' already exists.")
            else:
                print(f"Error creating directory: {e}")
                print(f"Command: {e.cmd}")
                print(f"Return code: {e.returncode}")
                print(f"Stdout: {e.stdout.decode()}")
                print(f"Stderr: {e.stderr.decode()}")
                raise  # Re-raise the exception to signal failure

    finally:
        lowerPrivileges()


if __name__ == '__main__':
    try:
        makeNewUserDir("testuser123")  # Example usage
        print("User directory created successfully.")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

