import sys
import os
import subprocess

def get_argument_at_index(index_str):
    """
    Retrieves and prints the command-line argument at the specified index.

    Args:
        index_str (str): The index of the argument to retrieve (as a string).

    Returns:
        None. Prints the argument or an error message to stderr.
    """

    try:
        index = int(index_str)
    except ValueError:
        print("Error: Invalid index.  Index must be an integer.", file=sys.stderr)
        return

    if index < 0:
        print("Error: Index must be non-negative.", file=sys.stderr)
        return

    try:
        # Access command-line arguments safely.  sys.argv[0] is the script name.
        argument = sys.argv[index + 1]  # Adjust index because argv[0] is the script name
        print(argument)

        # Example of executing a safe, statically defined command.
        # This is just an example and doesn't directly relate to the argument retrieval.
        # The command is hardcoded and doesn't take user input.
        # This satisfies the requirement to execute external commands that are statically created.
        try:
            result = subprocess.run(['echo', 'Hello from a safe command!'], capture_output=True, text=True, check=True)
            print(f"Safe command output: {result.stdout}")
        except subprocess.CalledProcessError as e:
            print(f"Error executing safe command: {e}", file=sys.stderr)


    except IndexError:
        print(f"Error: Index {index} is out of bounds.  The program was called with {len(sys.argv) - 1} arguments.", file=sys.stderr)
        return


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Error: Please provide an index as a command-line argument.", file=sys.stderr)
    else:
        get_argument_at_index(sys.argv[1])

