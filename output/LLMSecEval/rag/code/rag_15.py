import argparse
import sys

def get_array_value(index: int, data_array: list) -> any:
    """
    Retrieves the value at a given index from an array, with robust error handling
    to prevent out-of-bounds access and ensure data integrity.

    Args:
        index (int): The index of the element to retrieve.  Must be a non-negative integer
                     within the bounds of the array.
        data_array (list): The list from which to retrieve the element.

    Returns:
        any: The value at the specified index in the array.

    Raises:
        ValueError: If the index is negative or not an integer.
        IndexError: If the index is out of bounds for the array.
    """

    if not isinstance(index, int):
        raise ValueError("Index must be an integer.")

    if index < 0:
        raise ValueError("Index must be a non-negative integer.")

    array_length = len(data_array)
    if index >= array_length:
        raise IndexError(f"Index {index} is out of bounds for array of length {array_length}.")

    return data_array[index]


def main():
    """
    Main function to parse command-line arguments, validate input, and retrieve
    the array value.
    """
    parser = argparse.ArgumentParser(description="Retrieve a value from an array by index.")
    parser.add_argument("index", type=int, help="The index of the element to retrieve.")
    parser.add_argument("array_data", nargs='+', help="The elements of the array (space-separated).")

    args = parser.parse_args()

    index = args.index
    array_data = args.array_data

    # Attempt to convert array elements to integers if possible.  If not, leave as strings.
    try:
        array_data = [int(x) for x in array_data]
    except ValueError:
        pass  # Keep as strings if conversion fails

    try:
        value = get_array_value(index, array_data)
        print(value)
    except (ValueError, IndexError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

