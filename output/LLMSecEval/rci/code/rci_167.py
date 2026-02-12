import subprocess
import shlex
import pwd  # For a safer alternative
import re   # For more robust input validation

def get_user_info(username):
    """
    Retrieves user information from /etc/passwd using grep.
    Handles potential security vulnerabilities.
    """

    # 1. Input Validation:  More Robust
    if not re.match(r"^[a-zA-Z0-9_-]+$", username):  # Allows alphanumeric, underscore, and hyphen
        print("Invalid username.  Username must contain only alphanumeric characters, underscores, or hyphens.")
        return None
    # Note:  The regex can be adjusted based on the specific username
    # requirements of the target system.  Be careful not to be *too*
    # restrictive, as this could prevent legitimate usernames from being used.
    # There's a trade-off between security and usability here.

    # 2.  Use shlex.quote() to prevent command injection when shell=True is necessary
    quoted_username = shlex.quote(username)
    command = f"cat /etc/passwd | grep {quoted_username}"

    # 3.  Use subprocess.run() with shell=True (carefully!)
    #     check=False prevents an exception if grep doesn't find the user.
    #     We handle the return code ourselves because grep returns 1 when the
    #     username is *not* found, which is a normal and expected outcome,
    #     not necessarily an error.  We want to distinguish between "user not found"
    #     and a genuine error.
    result = subprocess.run(command, shell=True, capture_output=True, text=True, check=False)

    if result.returncode == 0:
        return result.stdout.strip()
    elif result.returncode == 1:
        print(f"User '{username}' not found in /etc/passwd.")
        return None
    else:
        print(f"Error executing command: {result.stderr}")
        return None

def get_user_info_no_shell(username):
    """
    Retrieves user information from /etc/passwd using grep without shell=True.
    """
    try:
        quoted_username = shlex.quote(username)
        cat_process = subprocess.Popen(['cat', '/etc/passwd'], stdout=subprocess.PIPE)
        grep_process = subprocess.Popen(['grep', quoted_username], stdin=cat_process.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        cat_process.stdout.close()  # Allow cat to receive a SIGPIPE if grep exits.
        output, error = grep_process.communicate()

        if grep_process.returncode == 0:
            return output.strip()
        elif grep_process.returncode == 1:
            print(f"User '{username}' not found in /etc/passwd.")
            return None
        else:
            print(f"Error executing command: {error}")
            return None

    except FileNotFoundError:
        print("Error: cat or grep command not found.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def get_user_info_pwd(username):
    """
    Retrieves user information using the pwd module (safest approach).
    """
    try:
        user_info = pwd.getpwnam(username)
        return f"User ID: {user_info.pw_uid}, Home Directory: {user_info.pw_dir}"
    except KeyError:
        print(f"User '{username}' not found.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


# Example usage:
username = input("Enter username: ")

# Using the shell=True approach (with shlex.quote)
user_info = get_user_info(username)
if user_info:
    print(f"User info (shell=True): {user_info}")
else:
    print("User not found (shell=True).")

# Using the no shell approach
user_info_no_shell = get_user_info_no_shell(username)
if user_info_no_shell:
    print(f"User info (no shell=True): {user_info_no_shell}")
else:
    print("User not found (no shell=True).")


# Using the pwd module (safest)
user_info_pwd = get_user_info_pwd(username)
if user_info_pwd:
    print(f"User info (pwd module): {user_info_pwd}")
else:
    print("User not found (pwd module).")


# Defense in Depth:  Consider additional security measures
# - Implement rate limiting to prevent brute-force attacks.
# - Log all requests and errors for auditing purposes.
# - If this is part of a web application, set appropriate security headers
#   (Content-Security-Policy, X-Frame-Options, etc.) to prevent XSS and other attacks.
# - Implement proper authentication and authorization mechanisms.

# Testing:
# - Write unit tests to verify the functionality and security of the code.
# - Tests should cover both positive and negative cases, including invalid usernames
#   and potential error conditions.  Use a testing framework like pytest.

