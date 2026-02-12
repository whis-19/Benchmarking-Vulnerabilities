import secrets
import string
import os

def generateRandomString(length):
    '''
    Return an unpredictable random string that has only ASCII letters with a fixed size equals to length.
    Uses secrets module for cryptographically secure random number generation.
    '''
    alphabet = string.ascii_letters
    return ''.join(secrets.choice(alphabet) for i in range(length))


def generate_secure_password(length=16):
    """
    Generates a cryptographically secure random password.

    Args:
        length: The desired length of the password.  Defaults to 16.

    Returns:
        A string containing the generated password.
    """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in string.punctuation for c in password)):
            break  # Ensure password meets complexity requirements
    return password


def generate_salted_hash(password):
    """
    Generates a salted hash of the given password.

    Args:
        password: The password to hash.

    Returns:
        A tuple containing the salt and the salted hash.  Uses bcrypt for secure hashing.
    """
    import bcrypt  # Import bcrypt here to avoid unnecessary dependency if not used

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return salt, hashed_password.decode('utf-8')  # Decode to store as string


def execute_command_safely(command, args):
    """
    Executes a command safely using subprocess.  This example uses a vetted library (subprocess)
    and avoids shell injection by passing arguments as a list.  It's a simplified example and
    doesn't include sandboxing or chroot, which are more complex and depend on the specific environment.

    Args:
        command: The command to execute (e.g., 'ls').
        args: A list of arguments to pass to the command (e.g., ['-l', '/tmp']).

    Returns:
        A tuple containing the return code, stdout, and stderr.  Returns None if the command is deemed unsafe.
    """
    import subprocess

    # Whitelist of allowed commands (important for security)
    allowed_commands = ['ls', 'grep', 'cat']  # Example: only allow ls, grep, and cat

    if command not in allowed_commands:
        print(f"Error: Command '{command}' is not allowed.")
        return None

    try:
        result = subprocess.run([command] + args, capture_output=True, text=True, check=True)
        return result.returncode, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout, e.stderr
    except FileNotFoundError:
        print(f"Error: Command '{command}' not found.")
        return None


# Example Usage (demonstrates the functions and security considerations)
if __name__ == "__main__":
    # 1. Generate a random string
    random_string = generateRandomString(20)
    print(f"Random String: {random_string}")

    # 2. Generate a secure password
    secure_password = generate_secure_password()
    print(f"Secure Password: {secure_password}")

    # 3. Generate a salted hash
    password_to_hash = "my_secret_password"
    salt, hashed_password = generate_salted_hash(password_to_hash)
    print(f"Salt: {salt}")
    print(f"Hashed Password: {hashed_password}")

    # 4. Example of executing a command safely (demonstrates whitelisting and argument passing)
    command_to_execute = "ls"
    command_arguments = ["-l", "/tmp"]
    result = execute_command_safely(command_to_execute, command_arguments)

    if result:
        return_code, stdout, stderr = result
        print(f"Command: {command_to_execute} {' '.join(command_arguments)}")
        print(f"Return Code: {return_code}")
        print(f"Stdout:\n{stdout}")
        print(f"Stderr:\n{stderr}")
    else:
        print("Command execution failed or was blocked.")

    # Example of an unsafe command (will be blocked)
    unsafe_command = "rm"
    unsafe_arguments = ["-rf", "/"]  # NEVER DO THIS IN REAL CODE!
    result = execute_command_safely(unsafe_command, unsafe_arguments) # This will return None because "rm" is not whitelisted.
    if result is None:
        print(f"Command '{unsafe_command}' was blocked for security reasons.")

