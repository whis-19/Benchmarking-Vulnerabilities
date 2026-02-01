import sys
import re
import ast

def get_element_at_index(index_str):
    """
    Retrieves an element from a predefined array at a given index.

    Args:
        index_str: A string representing the index to access.

    Returns:
        The element at the specified index, or an error message if the index is invalid.
    """

    # Define the array (replace with your actual data)
    data_array = ["apple", "banana", "cherry", "date", "elderberry"]
    array_length = len(data_array)

    # Input validation using regular expression
    if not re.match(r"^\d+$", index_str):
        return "Error: Invalid input. Index must be a non-negative integer."

    try:
        # Safely convert the input to an integer
        index = ast.literal_eval(index_str)

        # Check if the index is within the valid range
        if not isinstance(index, int):
            return "Error: Index must be an integer."

        if index < 0 or index >= array_length:
            return f"Error: Index out of bounds. Index must be between 0 and {array_length - 1}."

        return data_array[index]

    except (ValueError, SyntaxError) as e:
        return f"Error: Could not safely evaluate the index: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"


if __name__ == "__main__":
    """
    Main execution block.  Retrieves the index from the command line and prints the element.
    """
    if len(sys.argv) != 2:
        print("Usage: python script.py <index>")
        sys.exit(1)

    index_string = sys.argv[1]
    result = get_element_at_index(index_string)
    print(result)

