import sys
import re
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def string_to_integer(s):
    """
    Converts a string to an integer, with input validation and DoS protection.

    Args:
        s: The string to convert.

    Returns:
        The integer representation of the string, or None if the string is not a valid integer.
    """
    if not isinstance(s, str):
        logging.warning(f"Invalid input type: {type(s)}. Expected string.")
        return None

    if len(s) > 100:  # Limit string length to prevent DoS
        logging.warning(f"Input string too long: {len(s)} characters.  Maximum allowed is 100.")
        return None

    # Use a regular expression to check if the string contains only digits
    if not re.match(r"^-?\d{1,10}$", s):  # Added digit limit to regex
        logging.warning(f"Invalid characters in input string: {s}.  Only digits and an optional leading minus sign are allowed.")
        return None

    try:
        num = int(s)
        if abs(num) > 2**31 - 1:  # Limit integer size to prevent potential resource exhaustion
            logging.warning(f"Integer out of range: {num}.  Must be within the 32-bit integer range.")
            return None  # Or raise an exception: ValueError("Integer too large")
        return num
    except ValueError:
        logging.exception(f"ValueError occurred while converting string to integer: {s}") # Log the full exception
        return None


def main():
    """
    Retrieves a command-line argument at a specified index and prints it.
    """
    if len(sys.argv) < 3:
        print("Error: Usage: python script.py <index_string> <argument_at_index>") # Consistent "Error:" prefix
        return

    index_string = sys.argv[1]

    # Validate the index string to ensure it's a valid integer
    index = string_to_integer(index_string)

    if index is None:
        logging.error(f"Invalid index provided: {index_string}")
        print("Error: Invalid input provided.")  # Generic user-facing message
        return

    # Validate the index range
    if index < 0:
        logging.error(f"Index must be a non-negative integer: {index}")
        print("Error: Index must be a non-negative integer.") # Consistent "Error:" prefix
        return

    if index >= len(sys.argv):
        logging.error(f"Index is out of range: {index}.  Number of arguments: {len(sys.argv)}")
        print("Error: Index is out of range.") # Consistent "Error:" prefix
        return

    try:
        argument_at_index = sys.argv[index]
        print(argument_at_index)
    except IndexError as e:
        logging.exception(f"IndexError occurred: {e}")
        print("Error: Index out of range.") # Consistent "Error:" prefix


if __name__ == "__main__":
    main()

