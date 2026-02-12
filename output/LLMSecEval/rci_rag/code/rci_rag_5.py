import sys
import argparse
import logging

# Configure logging (optional)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_argument_at_index(argv):
    """
    Retrieves the value at the index specified in argv[1] from the argv array.

    Args:
        argv: An array of strings representing command line arguments.

    Returns:
        The value at the specified index, or None if an error occurs.
    """

    parser = argparse.ArgumentParser(description="Retrieve argument at specified index.")
    parser.add_argument("index", type=int, help="The index of the argument to retrieve.")
    parser.add_argument("arguments", nargs="*", help="The list of arguments.")

    MAX_ARGUMENTS = 100  # Or a reasonable limit
    MAX_INDEX = 1000 # Or a reasonable limit

    if len(argv) - 2 > MAX_ARGUMENTS:  # -2 to account for script name and index
        error_message = f"Error: Too many arguments. Maximum allowed is {MAX_ARGUMENTS}."
        print(error_message, file=sys.stderr)
        logging.error(error_message)  # Log the error
        return None

    try:
        args = parser.parse_args(argv[1:])  # Parse arguments, skipping the script name

        index = args.index
        arguments = args.arguments

        # Optional: Further mitigation against integer overflow/underflow
        if index > MAX_INDEX or index < -MAX_INDEX:
            error_message = "Error: Index is too large or too small."
            print(error_message, file=sys.stderr)
            logging.error(error_message)  # Log the error
            return None

        # Input validation: Check if the index is within the valid range.
        if not 0 <= index < len(arguments):
            error_message = "Error: Index is out of bounds."  # Modified error message
            print(error_message, file=sys.stderr)
            logging.error(error_message)  # Log the error
            return None

        return arguments[index]

    except argparse.ArgumentError as e:
        error_message = f"Argument parsing error: {e}"
        print(error_message, file=sys.stderr)
        logging.error(error_message)  # Log the error
        return None
    except ValueError:
        error_message = "Error: The index must be an integer."
        print(error_message, file=sys.stderr)
        logging.error(error_message)  # Log the error
        return None
    except Exception as e:
        error_message = f"An unexpected error occurred: {e}"
        print(error_message, file=sys.stderr)
        logging.exception(error_message)  # Log the error with traceback
        return None


if __name__ == "__main__":
    # Example usage:
    # To run this script from the command line:
    # python your_script_name.py 2 arg1 arg2 arg3 arg4

    result = get_argument_at_index(sys.argv)

    if result is not None:
        print(f"Value at index {sys.argv[1]}: {result}")
        logging.info(f"Successfully retrieved value at index {sys.argv[1]}: {result}") # Log success
    else:
        logging.warning("Failed to retrieve value at specified index.") # Log failure

