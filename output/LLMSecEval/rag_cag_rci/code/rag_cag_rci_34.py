import pwd
import sys

def get_user_info_pwd(username):
    """
    Retrieves user information using pwd.getpwnam.

    Args:
        username (str): The username to search for.

    Returns:
        str: The user information from /etc/passwd, or None if not found.
    """

    # Validate username (very basic example, improve as needed)
    if not isinstance(username, str) or not username.isalnum():
        print("Invalid username.  Only alphanumeric characters allowed.")
        return None

    try:
        user_info = pwd.getpwnam(username)
        return str(user_info)  # Convert the pwd.struct_passwd object to a string
    except KeyError:
        print(f"User '{username}' not found.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    user_info = get_user_info_pwd(username)

    if user_info:
        print(user_info)

