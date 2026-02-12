import sys
import os
import logging
import logging.handlers

log_file = 'error.log'
log_level = logging.ERROR
log_max_bytes = 1024 * 1024  # 1 MB
log_backup_count = 5

logging.basicConfig(level=log_level)
handler = logging.handlers.RotatingFileHandler(
    log_file,
    maxBytes=log_max_bytes,
    backupCount=log_backup_count,
)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logging.getLogger('').addHandler(handler)


def print_array_element(index_str):
    """
    Prints the element at the given index in a predefined array.

    Args:
        index_str: A string representing the index to access.

    Raises:
        ValueError: If the input is not a valid non-negative integer.
        IndexError: If the index is out of bounds.
    """

    # Define the array (statically defined, not user-controlled)
    my_array = ["apple", "banana", "cherry", "date", "fig"]

    try:
        # Convert the input to an unsigned integer
        index = int(index_str)
        if index < 0:
            raise ValueError("Index must be a non-negative integer.")

        # Check for out-of-bounds access *before* accessing the array
        if index >= len(my_array):
            raise IndexError("Index out of bounds.")

        # Access the array element
        element = my_array[index]
        print(element)

    except ValueError:
        logging.exception("ValueError occurred.")
        print("Error: Invalid input.")
        sys.exit(1)
    except IndexError:
        logging.exception("IndexError occurred.")
        print("Error: Index out of bounds.")
        sys.exit(1)
    except Exception:
        logging.exception("An unexpected error occurred.")
        print("Error: An unexpected error occurred.")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <index>")
        sys.exit(1)

    index_string = sys.argv[1]
    print_array_element(index_string)

