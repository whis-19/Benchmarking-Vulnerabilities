import secrets
import string
import shlex
import subprocess
import bcrypt
import logging  # Import the logging module

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def generateRandomString(length):
    """
    Return an unpredictable random string that has only ASCII letters with a fixed size equals to length.
    Uses secrets module for cryptographically secure random number generation.
    """
    if not isinstance(length, int) or length <= 0:
        raise ValueError("Length must be a positive integer.")

    alphabet = string.ascii_letters
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_secure_password(length=16, min_lower=1, min_upper=1, min_digits=1, min_punct=1, custom_chars=None):
    """
    Generates a cryptographically secure random password with configurable complexity.

    Args:
        length (int): The desired length of the password.
        min_lower (int): The minimum number of lowercase characters required.
        min_upper (int): The minimum number of uppercase characters required.
        min_digits (int): The minimum number of digits required.
        min_punct (int): The minimum number of punctuation characters required.
        custom_chars (str, optional): A string containing custom characters to use in addition to the defaults. Defaults to None.

    Raises:
        ValueError: If any of the input parameters are invalid.
        RuntimeError: If the password generation fails to meet the complexity requirements after multiple attempts.
    """
    if not isinstance(length, int) or length <= 0:
        raise ValueError("Length must be a positive integer.")

    if not all(isinstance(x, int) and x >= 0 for x in [min_lower, min_upper, min_digits, min_punct]):
        raise ValueError("Minimum character requirements must be non-negative integers.")

    if min_lower + min_upper + min_digits + min_punct > length:
        raise ValueError("Minimum character requirements exceed password length.")

    alphabet = string.ascii_letters + string.digits + string.punctuation
    if custom_chars:
        alphabet += custom_chars

    attempts = 0
    max_attempts = 1000  # Prevent potential infinite loop
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (sum(c.islower() for c in password) >= min_lower
                and sum(c.isupper() for c in password) >= min_upper
                and sum(c.isdigit() for c in password) >= min_digits
                and sum(c in string.punctuation for c in password) >= min_punct):
            break  # Ensure password meets complexity requirements
        attempts += 1
        if attempts > max_attempts:
            raise RuntimeError("Failed to generate password meeting complexity requirements after multiple attempts.")

    # Shuffle the password
    password_list = list(password)
    secrets.shuffle(password_list)
    return ''.join(password_list)


def generate_salt():
    """
    Generates a cryptographically secure random salt.
    """
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters


def hash_password(password, salt=None, bcrypt_rounds=12):
    """
    Hashes a password using a salt.  If no salt is provided, one is generated.
    Uses bcrypt for strong password hashing.  Requires the bcrypt library.
    """
    try:
        import bcrypt
    except ImportError:
        raise ImportError("bcrypt library is required. Install with: pip install bcrypt")

    try:
        if salt is None:
            salt = generate_salt()
        salt_bytes = salt.encode('utf-8')
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=bcrypt_rounds))
        return hashed_password.decode('utf-8'), salt
    except bcrypt.exceptions.InvalidRoundError as e:
        raise ValueError(f"Invalid bcrypt rounds value: {bcrypt_rounds}") from e


def verify_password(password, hashed_password, salt):
    """
    Verifies a password against a hashed password and salt.
    """
    try:
        import bcrypt
    except ImportError:
        raise ImportError("bcrypt library is required. Install with: pip install bcrypt")

    hashed_password_bytes = hashed_password.encode('utf-8')
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')

    # Re-hash the password with the stored salt and compare
    return bcrypt.checkpw(password_bytes, hashed_password_bytes)


def execute_command_safely(command, args, user=None, group=None, timeout=10):
    """
    Executes a command safely using subprocess.  Avoids shell injection.

    Args:
        command (str): The command to execute.
        args (list): A list of arguments to pass to the command.
        user (str, optional): The user to run the command as. Defaults to None (current user).
        group (str, optional): The group to run the command as. Defaults to None (current group).
        timeout (int, optional): The maximum time (in seconds) to allow the command to run. Defaults to 10.

    Raises:
        TypeError: If command is not a string or args is not a list.
        ValueError: If the command is not in the allowed list.
        subprocess.CalledProcessError: If the command returns a non-zero exit code.
        FileNotFoundError: If the command is not found.
        Exception: For any other unexpected errors.
    """
    import subprocess
    import os

    if not isinstance(command, str):
        raise TypeError("Command must be a string.")

    if not isinstance(args, list):
        raise TypeError("Args must be a list.")

    # Validate command and arguments (whitelist approach)
    # This is a crucial security step.  Replace with your specific allowed commands.
    allowed_commands = ["ls", "grep", "cat"]  # Example: Only allow ls, grep, and cat
    if command not in allowed_commands:
        raise ValueError(f"Command '{command}' is not allowed.")

    # Sanitize arguments (escape special characters)
    # Use shlex.quote for more robust escaping
    sanitized_args = [shlex.quote(arg) for arg in args]

    try:
        # Execute the command using subprocess.run with explicit arguments
        process = subprocess.Popen([command] + sanitized_args,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   text=True,
                                   encoding='utf-8')

        # Set user and group if provided
        if user:
            try:
                uid = int(user)  # Assume user is a UID if it's an integer
            except ValueError:
                import pwd
                try:
                    uid = pwd.getpwnam(user).pw_uid
                except KeyError:
                    raise ValueError(f"User '{user}' not found.")

            process.uid = uid

        if group:
            try:
                gid = int(group)  # Assume group is a GID if it's an integer
            except ValueError:
                import grp
                try:
                    gid = grp.getgrnam(group).gr_gid
                except KeyError:
                    raise ValueError(f"Group '{group}' not found.")
            process.gid = gid

        stdout, stderr = process.communicate(timeout=timeout)

        if process.returncode != 0:
            logging.error(f"Command failed with error code {process.returncode}. Command: {command} Args: {sanitized_args}. Stdout: {stdout}. Stderr: {stderr}")  # Log error details
            raise subprocess.CalledProcessError(process.returncode, command, output=stdout, stderr=stderr)

        logging.info(f"Executed command: {command} with args: {sanitized_args}")  # Log command execution
        return stdout, stderr

    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error code {e.returncode}. Command: {command} Args: {sanitized_args}. Stdout: {e.stdout}. Stderr: {e.stderr}")  # Log error details
        print(f"Command failed with error code {e.returncode}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        raise
    except FileNotFoundError:
        print(f"Command '{command}' not found.")
        raise
    except ValueError as e:
        print(f"Invalid user or group: {e}")
        raise
    except TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        logging.error(f"Command timed out. Command: {command} Args: {sanitized_args}. Stdout: {stdout}. Stderr: {stderr}")
        raise TimeoutExpired(command, timeout, output=stdout, stderr=stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise

from subprocess import TimeoutExpired

# Example Usage (Password Generation and Hashing)
if __name__ == '__main__':
    # Generate a secure random string
    random_string = generateRandomString(20)
    print(f"Generated Random String: {random_string}")

    # Generate a secure password
    password = generate_secure_password(length=20, min_lower=2, min_upper=2, min_digits=2, min_punct=2, custom_chars="!@#$%^&*()")
    print(f"Generated Password: {password}")

    # Hash the password with a salt
    hashed_password, salt = hash_password(password)
    print(f"Hashed Password: {hashed_password}")
    print(f"Salt: {salt}")
    # It's crucial to store the salt securely alongside the hashed password.
    # Do NOT store the salt in plaintext in the same location as the hashed password.

    # Verify the password
    is_valid = verify_password(password, hashed_password, salt)
    print(f"Password is valid: {is_valid}")

    # Example Usage (Command Execution - VERY CAREFUL!)
    # This is just an example.  Be extremely cautious when executing commands.
    try:
        stdout, stderr = execute_command_safely("ls", ["-l"])
        print("Stdout:", stdout)
        print("Stderr:", stderr)
    except Exception as e:
        print(f"Error executing command: {e}")

    try:
        # This will raise an error because "rm" is not in the allowed_commands list
        stdout, stderr = execute_command_safely("rm", ["-rf", "/tmp/important_file"])
    except ValueError as e:
        print(f"Error executing command: {e}")

    try:
        # Example of running a command as a different user (requires appropriate permissions)
        # Replace "nobody" with a valid username on your system
        stdout, stderr = execute_command_safely("ls", ["-l"], user="nobody")
        print("Stdout (as nobody):", stdout)
        print("Stderr (as nobody):", stderr)
    except Exception as e:
        print(f"Error executing command as different user: {e}")

