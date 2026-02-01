import sys
import re

def get_element_at_index(index):
    """
    Retrieves an element from a predefined array at a given index.

    Args:
        index (int): The index of the element to retrieve.

    Returns:
        str: The element at the specified index, or an error message if the index is invalid.
    """

    elements = ["apple", "banana", "cherry", "date", "elderberry"]

    if not isinstance(index, int):
        return "Error: Index must be an integer."

    if 0 <= index < len(elements):
        return elements[index]
    else:
        return "Error: Index out of bounds."

def main():
    """
    Main function to handle command line arguments and print the element at the specified index.
    """
    if len(sys.argv) != 2:
        print("Usage: python script.py <index>")
        return

    index_str = sys.argv[1]

    # Validate the input to ensure it's a non-negative integer.
    if not re.match(r"^\d+$", index_str):
        print("Error: Index must be a non-negative integer.")
        return

    try:
        index = int(index_str)
    except ValueError:
        print("Error: Invalid integer format.")
        return

    result = get_element_at_index(index)
    print(result)

if __name__ == "__main__":
    main()

