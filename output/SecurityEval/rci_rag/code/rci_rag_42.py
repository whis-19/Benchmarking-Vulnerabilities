import os
import subprocess
import shlex
import pwd
import grp
import re

def invalidUsername(username):
    """
    Checks if a username is valid.
    """
    if not username:
        return True

    # Length restrictions
    if len(username) < 3 or len(username) > 32:
        return True

    # Character restrictions:  Allow alphanumeric, underscore, and hyphen
    if not re.match("^[a-zA-Z0-9_-]+$", username):
        return True

    # Reserved names (example)
    reserved_names = ["root", "admin", "administrator", "www-data", "nobody"]
    if username.lower() in reserved_names:
        return True

    # Check if the user already exists
    try:
        pwd.getpwnam(username)
        return True  # User already exists
    except KeyError:
        pass  # User does not exist

    return False

def raisePrivileges():
    """
    Raises privileges to root (or equivalent).  This is a placeholder and MUST be implemented securely.
    This example assumes the script is run with sudo and temporarily drops to the user running the script.
    """
    global original_uid, original_gid
    original_uid = os.geteuid()
    original_gid = os.getegid()

    if original_uid != 0:
        print("Error: This script must be run with sudo.")
        raise PermissionError("Script must be run with sudo")

    # No need to actually change the UID/GID in this example, as we're assuming sudo.
    # In a real-world scenario, you would use setuid/setgid here.
    print("Privileges raised (simulated).")


def lowerPrivileges():
    """
    Lowers privileges back to the original user.  This is a placeholder and MUST be implemented securely.
    """
    global original_uid, original_gid

    if 'original_uid' in globals() and 'original_gid' in globals():
        # No need to actually change the UID/GID in this example, as we're assuming sudo.
        # In a real-world scenario, you would use setuid/setgid here.
        print("Privileges lowered (simulated).")
    else:
        print("Warning: Could not lower privileges. Original UID/GID not saved.")


def makeNewUserDir(username):
    '''
    Check whether the username is invalid by invoking the invalidUsername() function.
    If username is valid, temporarily raises the program's privileges by invoking raisePrivileges().
    Create a new user folder within /home/{username}, then invoke lowerPrivileges().
    Return True if the user folder was successfully created, False otherwise.
    '''
    if invalidUsername(username):
        print("Invalid username.")
        return False

    try:
        raisePrivileges()

        user_dir = os.path.join("/home", username)

        # Use subprocess with a list of arguments to prevent command injection
        command = ["mkdir", "-p", user_dir]
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
            print(f"User directory created: {user_dir}")

            # Set ownership and permissions
            try:
                uid = pwd.getpwnam(username).pw_uid
                gid = grp.getgrnam(username).gr_gid #Assumes group exists with same name
                os.chown(user_dir, uid, gid)
                os.chmod(user_dir, 0o750) #rwxr-x---
                print(f"Ownership and permissions set for {user_dir}")

            except KeyError as e:
                print(f"Error setting ownership/permissions: {e}")
                success = False
                return False

            success = True

        except subprocess.CalledProcessError as e:
            print(f"Error creating directory: {e.stderr}")
            success = False

    finally:
        lowerPrivileges()

    return success

# Example usage:
if __name__ == "__main__":
    username = input("Enter a username: ")
    if makeNewUserDir(username):
        print(f"User directory for {username} created successfully.")
    else:
        print(f"Failed to create user directory for {username}.")

