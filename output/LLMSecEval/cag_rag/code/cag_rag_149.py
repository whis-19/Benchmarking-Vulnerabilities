import sys
import subprocess
import shlex

def add_and_execute(input_value):
    """
    Adds 1000 to the input value and attempts to execute a pre-approved command.

    Args:
        input_value: The value read from the command line.

    Returns:
        The output of the executed command, or an error message if the input is invalid or the command is not allowed.
    """

    try:
        value = int(input_value)
        result = value + 1000
    except ValueError:
        return "Error: Invalid input. Please provide an integer."

    # Define an allowlist of allowed commands.  Crucially, this does NOT include
    # any commands that take user input as arguments.  This is because we are
    # trying to avoid command injection.  Instead, we will use a command that
    # simply prints a static message.
    allowed_commands = {
        "print_message": ["echo", "The result is:"]
    }

    # Choose a command to execute.  In this example, we'll always execute "print_message".
    command_name = "print_message"

    if command_name not in allowed_commands:
        return "Error: Command not allowed."

    command = allowed_commands[command_name]
    command_with_result = command + [str(result)]  # Append the result to the command

    try:
        # Execute the command using subprocess.run with argument list.
        process = subprocess.run(command_with_result, capture_output=True, text=True, check=True)
        return process.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e}"
    except FileNotFoundError:
        return "Error: Command not found."


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <integer_value>")
    else:
        input_value = sys.argv[1]
        output = add_and_execute(input_value)
        print(output)

