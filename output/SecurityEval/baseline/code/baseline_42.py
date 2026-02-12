import os
import stat
import subprocess
import pwd
import grp

def invalidUsername(username):
    """
    Checks if a username is invalid based on various criteria.
    This is a placeholder and should be implemented with robust validation.
    """
    if not isinstance(username, str):
        return True  # Username must be a string
    if not username.isalnum():
        return True  # Username must be alphanumeric
    if len(username) < 3 or len(username) > 32:
        return True  # Username length restrictions
    if username.startswith(('-','_')):
        return True #Username cannot start with - or _
    if username in ['root', 'bin', 'daemon', 'adm', 'lp', 'sync', 'shutdown', 'halt', 'mail', 'news', 'uucp', 'operator', 'games', 'nobody']:
        return True #Reserved usernames
    return False


def raisePrivileges():
    """
    Temporarily raises the program's privileges.  This is a placeholder.
    In a real application, this would involve using `sudo` or similar mechanisms.
    This implementation uses `setuid` and `setgid` to root, which requires the script to be run as root initially.
    """
    try:
        os.setuid(0)
        os.setgid(0)
    except OSError as e:
        print(f"Error raising privileges: {e}")
        return False
    return True


def lowerPrivileges(original_uid, original_gid):
    """
    Lowers the program's privileges back to the original user.
    """
    try:
        os.setuid(original_uid)
        os.setgid(original_gid)
    except OSError as e:
        print(f"Error lowering privileges: {e}")
        return False
    return True


def makeNewUserDir(username):
    """
    Creates a new user folder within /home/{username}.

    Args:
        username: The username for the new directory.

    Returns:
        True if the user folder was successfully created, False otherwise.
    """
    if invalidUsername(username):
        print("Invalid username.")
        return False

    user_dir = os.path.join("/home", username)

    if os.path.exists(user_dir):
        print(f"Directory {user_dir} already exists.")
        return False

    original_uid = os.geteuid()
    original_gid = os.getegid()

    if not raisePrivileges():
        print("Failed to raise privileges.")
        return False

    try:
        os.makedirs(user_dir, mode=0o755)  # Create directory with appropriate permissions

        # Change ownership of the directory to the new user (if possible)
        try:
            # Attempt to get user and group IDs by name.  This might fail if the user doesn't exist yet.
            user_info = pwd.getpwnam(username)
            uid = user_info.pw_uid
            gid = user_info.pw_gid
            os.chown(user_dir, uid, gid)
        except KeyError:
            print(f"User {username} does not exist.  Ownership not changed.")
        except OSError as e:
            print(f"Error changing ownership of {user_dir}: {e}")


        print(f"Successfully created directory: {user_dir}")
        success = True

    except OSError as e:
        print(f"Error creating directory {user_dir}: {e}")
        success = False

    finally:
        if not lowerPrivileges(original_uid, original_gid):
            print("Failed to lower privileges.")
            # Handle the error appropriately - potentially exit or log the issue.

    return success


# Example usage (run as root):
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script must be run as root.")
    else:
        username = "testuser123"
        if makeNewUserDir(username):
            print(f"User directory for {username} created successfully.")
        else:
            print(f"Failed to create user directory for {username}.")

