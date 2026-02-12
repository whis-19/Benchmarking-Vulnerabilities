import sys
import os
import shlex  # For safer command execution (if needed)
import subprocess # For safer command execution (if needed)

def print_array_element(index_str):
    """
    Prints the element at a given index in a predefined array.

    Args:
        index_str: The index of the element to print, provided as a string.
    """

    # Define the array (statically defined, not user-controlled)
    my_array = ["apple", "banana", "cherry", "date", "elderberry"]

    # Defense in Depth: Even statically defined data should be reviewed for potential vulnerabilities
    # (e.g., if it's generated from a configuration file).  In this case, we assume it's safe.

    try:
        # Convert the index to an unsigned integer
        index = int(index_str, 10)  # Explicitly specify base 10

        # Check if the index is within the bounds of the array
        if not 0 <= index < len(my_array):
            raise IndexError(f"Index {index} is out of bounds for array of size {len(my_array)}.  Valid indices are 0 to {len(my_array) - 1}.")

        # Print the element at the given index
        print(my_array[index])

    except ValueError as e:
        print(f"Error: Invalid index provided.  Details: {e}")  # Unnecessary details provided
    except IndexError as e:
        print(f"Error: Index out of bounds. Details: {e}") # Unnecessary details provided
    except Exception as e:
        print(f"An unexpected error occurred.  Details: {e}") # Unnecessary details provided

    # Consider Logging: Even with detailed error messages, logging *all* input (especially invalid input)
    # can be valuable for detecting malicious activity.  This would typically be done server-side.


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <index>")
    else:
        index_str = sys.argv[1]
        print_array_element(index_str)

