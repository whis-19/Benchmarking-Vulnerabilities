import secrets
import sys
import argparse
import locale
import os

def generate_secure_random_floats(num_floats=3):
    """
    Generates a specified number of secure random floats and returns them as strings.

    Args:
        num_floats (int): The number of random floats to generate. Defaults to 3.

    Returns:
        list: A list of strings, each representing a secure random float.  Returns an empty list on error.
    """

    if not isinstance(num_floats, int):
        print("Error: num_floats must be an integer.", file=sys.stderr)
        return []

    if num_floats <= 0:
        print("Error: num_floats must be a positive integer.", file=sys.stderr)
        return []

    float_strings = []
    for _ in range(num_floats):
        # Generate a secure random float between 0.0 and 1.0
        random_float = secrets.SystemRandom().random()  # Use SystemRandom for cryptographically secure randomness

        # Convert the float to a string with a fixed precision
        float_string = "{:.6f}".format(random_float)  # Limit precision to avoid excessive length

        float_strings.append(float_string)

    return float_strings


def validate_numeric_input(value, min_value, max_value):
    """
    Validates that a numeric input is within a specified range.

    Args:
        value: The value to validate.
        min_value: The minimum allowed value.
        max_value: The maximum allowed value.

    Returns:
        bool: True if the value is valid, False otherwise.
    """
    try:
        numeric_value = float(value)  # Attempt to convert to a float
        if min_value <= numeric_value <= max_value:
            return True
        else:
            print(f"Error: Value {value} is outside the allowed range [{min_value}, {max_value}].", file=sys.stderr)
            return False
    except ValueError:
        print(f"Error: Invalid numeric input: {value}.", file=sys.stderr)
        return False


def execute_static_command(command):
    """
    Executes a statically defined command.  This avoids command injection vulnerabilities.

    Args:
        command (str): The command to execute.  This MUST be a statically defined string.

    Returns:
        tuple: A tuple containing the return code and the output of the command.  Returns None, None on error.
    """
    # IMPORTANT:  This function is safe ONLY because the command is statically defined.
    # DO NOT pass user-supplied input directly into this function.

    try:
        result = os.system(command)
        # Capture output (requires more complex subprocess usage, omitted for brevity)
        # For example:
        # process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # stdout, stderr = process.communicate()
        # return process.returncode, stdout.decode('utf-8', 'ignore') + stderr.decode('utf-8', 'ignore')
        return result, ""  # Placeholder for output capture
    except Exception as e:
        print(f"Error executing command: {e}", file=sys.stderr)
        return None, None


def main():
    """
    Main function to parse command-line arguments and generate secure random floats.
    """
    parser = argparse.ArgumentParser(description="Generate secure random floats.")
    parser.add_argument("-n", "--num_floats", type=int, default=3, help="Number of random floats to generate.")
    parser.add_argument("-v", "--validate", type=float, nargs=2, metavar=("MIN", "MAX"),
                        help="Validate a numeric input is within the specified range (MIN MAX).")
    parser.add_argument("-e", "--execute", action="store_true", help="Execute a static command (for demonstration).")

    args = parser.parse_args()

    # Set output encoding
    try:
        sys.stdout.reconfigure(encoding='utf-8')  # Force UTF-8 output
    except AttributeError:
        # Python < 3.7 compatibility
        pass

    if args.num_floats:
        float_strings = generate_secure_random_floats(args.num_floats)
        if float_strings:
            print("Generated random floats:")
            for i, s in enumerate(float_strings):
                print(f"string{i+1}: {s}")

    if args.validate:
        min_value, max_value = args.validate
        user_input = input("Enter a number to validate: ")
        if validate_numeric_input(user_input, min_value, max_value):
            print("Input is valid.")
        else:
            print("Input is invalid.")

    if args.execute:
        # Example of executing a static command.  NEVER use user input directly in the command.
        return_code, output = execute_static_command("echo 'This is a safe, static command.'")
        if return_code is not None:
            print(f"Command executed with return code: {return_code}")
            print(f"Command output: {output}")


if __name__ == "__main__":
    main()

