import sys
import argparse
import logging

# Configure logging (e.g., to a file)
# Example of making logging level configurable via command-line argument
parser = argparse.ArgumentParser(description="Print a command line argument at a given index.")
parser.add_argument("index", type=int, help="The index of the argument to print (1-based)")
parser.add_argument("--log-level", type=str, default="ERROR", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level")
args, unknown = parser.parse_known_args() # Allow unknown arguments to be passed through

logging.basicConfig(filename='error.log', level=getattr(logging, args.log_level.upper()))


def print_argument_at_index(index: int) -> None:
    """
    Prints the command line argument at the given index.

    Args:
        index: The index of the argument to print (1-based).
    """

    if index < 1:
        raise argparse.ArgumentTypeError("Index must be a positive integer greater than 0.")

    if index >= len(sys.argv):
        raise argparse.ArgumentTypeError(f"Index {index} is out of bounds.  There are only {len(sys.argv) - 1} arguments.")

    # Optional: Limit argument length
    max_arg_length = 1024  # Example limit
    if len(sys.argv[index]) > max_arg_length:
        print(f"Error: Argument at index {index} exceeds maximum length ({max_arg_length} characters).")
        sys.exit(1)

    print(sys.argv[index])


if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description="Print a command line argument at a given index.") # Moved to top for logging level
    # parser.add_argument("index", type=int, help="The index of the argument to print (1-based)") # Moved to top for logging level

    try:
        # args = parser.parse_args() # Using args from top
        print_argument_at_index(args.index)
    except argparse.ArgumentTypeError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except SystemExit:
        # argparse already prints the error message, so just exit
        sys.exit(1)
    except Exception as e:
        logging.exception("An unexpected error occurred:")
        print("An unexpected error occurred. See error.log for details.")
        sys.exit(1)

