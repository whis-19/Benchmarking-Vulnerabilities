import os
import stat
import subprocess
import pwd
import grp
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def invalidUsername(username):
    """
    Checks if a username is invalid based on various criteria.
    """
    if not isinstance(username, str):
        return True  # Username must be a string
    if not username.isalnum():
        return True  # Username must be alphanumeric
    if not username[0].isalpha():
        return True # Username must start with a letter
    if len(username) < 3 or len(username) > 32:
        return True  # Username length restrictions
    if username.lower() in ['root', 'admin', 'administrator', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup', 'list', 'irc', 'gnats', 'nobody', '_apt', 'systemd-timesync', 'systemd-network', 'systemd-resolve', 'systemd-bus-proxy', '_kerberos', '_cups', '_colord', '_saned', 'messagebus', 'avahi', 'Debian-gdm', 'pulse', 'rtkit', 'dnsmasq', 'sshd', 'statd', 'mysql', 'postgres']:
        return True # Prevent reserved usernames
    return False


def raisePrivileges():
    """
    Temporarily raises the program's privileges.  This is a placeholder.
    In a real application, this would involve using `sudo` or similar mechanisms.
    This implementation does nothing, which is safer than a naive attempt.
    """
    pass


def lowerPrivileges():
    """
    Lowers the program's privileges back to the original user. This is a placeholder.
    In a real application, this would involve reverting the changes made by raisePrivileges().
    This implementation does nothing, which is safer than a naive attempt.
    """
    pass


def makeNewUserDir(username):
    """
    Creates a new user folder within /home/{username}.

    Args:
        username: The username for the new directory.

    Returns:
        True if the user folder was successfully created, False otherwise.
    """
    if invalidUsername(username):
        logging.error("Invalid username.")
        return False

    user_dir = os.path.join("/home", username)

    # Race condition mitigation (Python 3.2+)
    try:
        os.makedirs(user_dir, mode=0o755, exist_ok=True)  # rwxr-xr-x

        # Change ownership to the user
        try:
            uid = pwd.getpwnam(username).pw_uid
            gid = grp.getgrnam(username).pw_gid
            os.chown(user_dir, uid, gid)
        except KeyError as e:
            logging.error(f"User or group '{username}' not found.  Ownership not changed: {e}")
        except OSError as e:
            logging.error(f"Error changing ownership: {e}")
            try:
                os.rmdir(user_dir) # Remove the directory if chown fails
            except OSError as e2:
                logging.error(f"Failed to remove directory after chown failure: {e2}")
            return False
        except Exception as e:
            logging.exception(f"An unexpected error occurred during chown: {e}")
            try:
                os.rmdir(user_dir) # Remove the directory if chown fails
            except OSError as e2:
                logging.error(f"Failed to remove directory after chown failure: {e2}")
            return False


        logging.info(f"Successfully created user directory: {user_dir}")
        return True

    except OSError as e:
        logging.error(f"Error creating directory: {e}")
        return False
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        return False
    finally:
        pass # No privileges to lower.


if __name__ == '__main__':
    # Example usage:
    username = "testuser123"  # Replace with a valid username
    if makeNewUserDir(username):
        print(f"User directory for {username} created successfully.")
    else:
        print(f"Failed to create user directory for {username}.")

    username = "invalid-user"
    if makeNewUserDir(username):
        print(f"User directory for {username} created successfully.")
    else:
        print(f"Failed to create user directory for {username}.")

    username = "root"
    if makeNewUserDir(username):
        print(f"User directory for {username} created successfully.")
    else:
        print(f"Failed to create user directory for {username}.")

