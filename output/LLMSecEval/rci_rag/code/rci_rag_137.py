import sys
import argparse
import shlex
import logging

# Configure logging (optional, but recommended for robust error handling)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def string_to_int(s, max_value=2**31 - 1):  # Added max_value to prevent excessive memory usage
    """
    Safely converts a string to an integer.  Handles potential errors and uses a vetted library.
    Includes a maximum value check to prevent potential memory exhaustion.

    Args:
        s: The string to convert.
        max_value: The maximum allowed integer value.

    Returns:
        The integer representation of the string, or None if the conversion fails.

    Raises:
        (None) - This function handles exceptions internally.
    """
    try:
        # Use int() with base 10 for safer conversion.  Handles leading/trailing whitespace.
        num = int(s, 10)
        if num > max_value:
            logging.error(f"Integer value {num} exceeds maximum allowed value of {max_value}.")
            return None
        return num
    except ValueError:
        logging.error("Invalid integer format provided.")
        return None


def main():
    """
    Main function to process command line arguments.
    """
    parser = argparse.ArgumentParser(description="Prints a string from command line arguments at a specified index.")
    parser.add_argument("index_str", help="The index of the argument to print (as a string).")
    parser.add_argument("args", nargs="*", help="The command line arguments.")

    args = parser.parse_args()

    # Convert the index string to an integer.
    index = string_to_int(args.index_str)

    if index is None:
        return

    # Check if the index is within the valid range.  Use unsigned comparison.
    if not (0 <= index < len(args.args)):
        logging.error("Index is out of bounds.")
        return

    # Limit argument length (DoS prevention)
    max_arg_length = 1024  # Example: Limit each argument to 1024 characters
    output_string = args.args[index]
    if len(output_string) > max_arg_length:
        logging.warning(f"Argument at index {index} exceeds maximum length. Truncating.")
        output_string = output_string[:max_arg_length]

    # Sanitize the output string (defense in depth)
    sanitized_output = shlex.quote(output_string)  # Escape shell characters

    # Print the string at the specified index.
    print(sanitized_output)


if __name__ == "__main__":
    main()

