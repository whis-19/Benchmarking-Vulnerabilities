import sys
import os
import shlex  # Import for safer command construction (if needed - see comments)
import logging # Import for logging
import subprocess

# Configure logging (optional, but recommended for production)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_element_at_index(data_array, index):
    """
    Retrieves an element from the data_array at the specified index,
    handling potential errors and ensuring index validity.

    Args:
        data_array: The list of elements to access.
        index: The index of the element to retrieve.

    Returns:
        The element at the specified index, or None if the index is invalid.
    """
    if not isinstance(index, int):
        logging.error("Invalid index type: %s", type(index)) # Log the error
        print("Error: Invalid input.")  # Generic error message
        return None

    if index < 0 or index >= len(data_array):
        logging.error("Index out of bounds: index=%s, array_length=%s", index, len(data_array)) # Log the error
        print("Error: Invalid input.")  # Generic error message
        return None

    return data_array[index]


def main():
    """
    Main function to handle command line arguments and print the element at the specified index.
    """

    data = ["apple", "banana", "cherry", "date", "elderberry"]  # Example data array
    MAX_INDEX = 100  # Example limit to prevent excessively large index values (e.g., potential memory issues)

    if len(sys.argv) != 2:
        print("Usage: python script.py <index>")
        return

    index_str = sys.argv[1]

    # Input Validation and Sanitization:  Check if the input is a valid integer
    if not index_str.isdigit():
        print("Error: Invalid input.")  # Generic error message
        logging.warning("Non-digit input received: %s", index_str) # Log the warning
        return

    try:
        index = int(index_str)
    except ValueError as e:  # Added 'as e'
        print("Error: Invalid input.")  # Generic error message
        logging.warning("Invalid integer format received: %s. Error: %s", index_str, str(e)) # Log the warning with the exception details
        return

    if index > MAX_INDEX:
        print("Error: Invalid input.") # Generic error message
        logging.warning("Index exceeds maximum allowed value: index=%s, MAX_INDEX=%s", index, MAX_INDEX)
        return


    # Retrieve and print the element
    element = get_element_at_index(data, index)

    if element is not None:
        print(f"Element at index {index}: {element}")

        # DO NOT construct commands directly using string formatting with user-provided input!
        # This is extremely vulnerable to command injection.  Instead, use subprocess.run with a list of arguments.

        # Safer approach (if you absolutely need to execute a command):
        # command_args = ["echo", element]  # Pass arguments as a list
        # result = subprocess.run(command_args, capture_output=True, text=True, shell=False)
        # print(result.stdout)


if __name__ == "__main__":
    main()

