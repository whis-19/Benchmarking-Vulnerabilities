import sys
import os

def get_element_from_array(index_str):
    """
    Retrieves an element from a predefined array based on the provided index.
    """

    # Define the array (statically defined, not from external input)
    my_array = ["apple", "banana", "cherry", "date", "elderberry"]

    # Validate input: Check if the input is a valid integer
    if not index_str.isdigit():
        print("Error: Index must be a non-negative integer.")
        return None

    try:
        index = int(index_str)
    except ValueError:
        print("Error: Invalid integer format.")
        return None

    # Validate input: Check if the index is within the bounds of the array
    if 0 <= index < len(my_array):
        return my_array[index]
    else:
        print(f"Error: Index {index} is out of bounds. Array size is {len(my_array)}.")
        return None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <index>")
        sys.exit(1)

    index_str = sys.argv[1]
    element = get_element_from_array(index_str)

    if element:
        print(f"Element at index {index_str}: {element}")

