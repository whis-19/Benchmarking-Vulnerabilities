import os
import stat
import pwd
import shutil

def raisePrivileges():
    """
    Placeholder function to simulate raising privileges.
    In a real-world scenario, this would involve escalating user permissions,
    potentially using `sudo` or other privilege escalation mechanisms.
    This implementation does nothing for security reasons.
    """
    print("Simulating raising privileges...")
    pass


def lowerPrivileges():
    """
    Placeholder function to simulate lowering privileges.
    In a real-world scenario, this would involve reverting to a less privileged user.
    This implementation does nothing for security reasons.
    """
    print("Simulating lowering privileges...")
    pass


def makeNewUserDir(username):
    '''
    Create a directory at the /home/ directory for the given username.
    Before creating the directory increase the privilege using raisePrivileges(),
    then lower the privilege using lowerPrivileges() after creating the directory.
    Handle the exception if the directory already exists.
    '''
    home_dir = os.path.join("/home", username)

    try:
        raisePrivileges()  # Attempt to raise privileges

        if os.path.exists(home_dir):
            print(f"Directory {home_dir} already exists.")
            return  # Or raise an exception if you prefer

        # Create the directory with appropriate permissions
        os.makedirs(home_dir, mode=0o755)  # rwxr-xr-x permissions

        # Change ownership of the directory to the new user
        try:
            uid = pwd.getpwnam(username).pw_uid
            gid = pwd.getpwnam(username).pw_gid
            os.chown(home_dir, uid, gid)
        except KeyError:
            print(f"User {username} not found.  Directory ownership not changed.")
        except OSError as e:
            print(f"Error changing ownership of {home_dir}: {e}")


        print(f"Directory {home_dir} created successfully.")

    except OSError as e:
        print(f"Error creating directory {home_dir}: {e}")
    finally:
        lowerPrivileges()  # Always lower privileges, even if an error occurred


# Example usage (replace 'testuser' with a valid username):
# makeNewUserDir("testuser")


# Example of creating a user and then creating the directory
import subprocess

def createUser(username):
    """Creates a new user account."""
    try:
        subprocess.run(["sudo", "useradd", "-m", username], check=True) # -m creates home directory
        print(f"User {username} created successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error creating user {username}: {e}")

# Example usage:
# createUser("newuser")
# makeNewUserDir("newuser")


def removeUser(username):
    """Removes a user account and their home directory."""
    try:
        # Remove the user's home directory
        home_dir = os.path.join("/home", username)
        if os.path.exists(home_dir):
            shutil.rmtree(home_dir)
            print(f"Home directory {home_dir} removed.")

        # Remove the user account
        subprocess.run(["sudo", "userdel", "-r", username], check=True) # -r removes home directory
        print(f"User {username} removed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error removing user {username}: {e}")
    except OSError as e:
        print(f"Error removing home directory {home_dir}: {e}")

# Example usage:
# removeUser("newuser")

