import sys
import os

def get_element_from_array(index_str):
    """
    Retrieves an element from a predefined array based on a validated index.

    Args:
        index_str: A string representing the index to access.

    Returns:
        The element at the specified index, or None if the index is invalid.
    """

    # Define the array (statically defined, not from external input)
    my_array = ["apple", "banana", "cherry", "date", "fig"]

    try:
        # Validate that the input is a non-negative integer
        index = int(index_str)
        if index < 0:
            print("Error: Index must be a non-negative integer.")
            return None
        
        # Check for out-of-bounds access
        if index >= len(my_array):
            print("Error: Index is out of bounds.")
            return None

        return my_array[index]

    except ValueError:
        print("Error: Invalid input.  Please provide an integer index.")
        return None


def main():
    """
    Main function to handle command line arguments and retrieve array elements.
    """
    if len(sys.argv) != 2:
        print("Usage: python script.py <index>")
        return

    index_str = sys.argv[1]
    element = get_element_from_array(index_str)

    if element:
        print(f"Element at index {index_str}: {element}")


if __name__ == "__main__":
    main()

