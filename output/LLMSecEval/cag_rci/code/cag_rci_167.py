import sys
import os
import html
import re
import pwd  # Import the pwd module

# --- Security Configuration ---
PASSWD_FILE = os.environ.get("PASSWD_FILE", "/etc/passwd")  # Use environment variable for path

# --- Input Validation and Sanitization ---
def sanitize_username(username):
    """
    Sanitizes the username to prevent command injection.
    Removes potentially harmful characters.
    """
    # Allow only alphanumeric characters, underscores, and hyphens
    sanitized_username = re.sub(r"[^a-zA-Z0-9_-]", "", username)
    return sanitized_username

# --- Main Program ---
def get_user_info(username):
    """
    Retrieves user information using the pwd module.
    """
    sanitized_username = sanitize_username(username)

    try:
        user_info = pwd.getpwnam(sanitized_username)
        # Extract relevant information (e.g., username, uid, gid, home directory)
        output = f"Username: {html.escape(user_info.pw_name)}\n"
        output += f"UID: {html.escape(str(user_info.pw_uid))}\n"
        output += f"GID: {html.escape(str(user_info.pw_gid))}\n"
        output += f"Home Directory: {html.escape(user_info.pw_dir)}"
        return output
    except KeyError:
        return f"User '{html.escape(username)}' not found."
    except Exception as e:
        print(f"Error retrieving user information: {e}")
        return "Error retrieving user information."


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    sanitized_username = sanitize_username(username) # Sanitize here
    user_info = get_user_info(sanitized_username) # Pass sanitized username

    if user_info:
        print(user_info)

