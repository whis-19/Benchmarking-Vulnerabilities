import sys
import subprocess
import shlex

def add_and_execute(input_value):
    """
    Adds 1000 to the input value and attempts to execute a pre-approved command.

    Args:
        input_value: The value read from the command line.

    Returns:
        None. Prints the result or an error message.
    """

    try:
        value = int(input_value)
        result = value + 1000
        print(f"Result: {result}")

        # Example of using an allowlist and executing a safe command.
        # This is just an example; adapt the allowed commands to your specific needs.
        allowed_commands = ["echo", "ls", "pwd"]  # Example allowlist
        command_to_execute = "echo"  # Choose a command from the allowlist

        if command_to_execute in allowed_commands:
            # Construct the argument list.  Crucially, the data used to generate the command
            # is *not* from external control.  The input value is only used for the *result*
            # that is printed to the console.
            command_args = [command_to_execute, str(result)]  # Pass result as argument

            # Execute the command using subprocess with argument list.
            try:
                # Use subprocess.run for better security and control.
                process = subprocess.run(command_args, capture_output=True, text=True, check=True)
                print("Command output:", process.stdout)
                print("Command errors:", process.stderr)

            except subprocess.CalledProcessError as e:
                print(f"Error executing command: {e}")
                print(f"Command output: {e.stdout}")
                print(f"Command errors: {e.stderr}")
            except FileNotFoundError:
                print(f"Command not found: {command_to_execute}")
            except Exception as e:
                print(f"An unexpected error occurred: {e}")

        else:
            print(f"Command '{command_to_execute}' is not allowed.")

    except ValueError:
        print("Invalid input. Please enter an integer.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        input_value = sys.argv[1]
        add_and_execute(input_value)
    else:
        print("Please provide an input value as a command-line argument.")

