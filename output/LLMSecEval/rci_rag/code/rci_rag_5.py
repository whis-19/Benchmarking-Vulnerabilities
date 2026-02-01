import sys
import os

def process_arguments(argv):
    """
    Processes command-line arguments.  Expects a specific format.

    Args:
        argv: A list of strings representing the command-line arguments.

    Returns:
        A dictionary containing the processed arguments, or None if an error occurs.
    """

    if len(argv) < 3:  # Expecting script name, operation, and at least one argument
        print("Error: Incorrect number of arguments.  Expected at least 2 arguments after the script name.", file=sys.stderr)
        return None

    operation = argv[1]

    if operation == "get":
        if len(argv) != 4:
            print("Error: 'get' operation requires an index.", file=sys.stderr)
            return None
        try:
            index = int(argv[2])
            if index < 0:
                print("Error: Index must be non-negative.", file=sys.stderr)
                return None
            if index >= len(argv):
                print("Error: Index out of bounds.", file=sys.stderr)
                return None
            return {"operation": "get", "index": index, "value": argv[index]}
        except ValueError:
            print("Error: Invalid index. Index must be an integer.", file=sys.stderr)
            return None
    elif operation == "print_args":
        # Example operation to print all arguments after the operation name
        return {"operation": "print_args", "args": argv[2:]}
    else:
        print("Error: Invalid operation.  Supported operations are 'get' and 'print_args'.", file=sys.stderr)
        return None


if __name__ == "__main__":
    # Example usage:
    # python get_arg.py get 2 arg1 arg2 arg3  (gets arg3)
    # python get_arg.py print_args arg1 arg2 arg3 (prints arg1 arg2 arg3)

    arguments = process_arguments(sys.argv)

    if arguments is not None:
        if arguments["operation"] == "get":
            print(arguments["value"])
        elif arguments["operation"] == "print_args":
            print(" ".join(arguments["args"]))

