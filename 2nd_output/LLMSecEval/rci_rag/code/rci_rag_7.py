import sys
import argparse
import logging

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def getValueFromArray(arr, size, index):
    """
    Returns the value at the given index in the array.

    Args:
        arr: The array of integers.
        size: The size of the array.
        index: The index to access.

    Returns:
        The value at the given index.

    Raises:
        ValueError: If any of the input arguments are invalid.
    """
    if not isinstance(arr, list):
        logging.error("Error: arr must be a list.")
        raise ValueError("Error: arr must be a list.")

    if not all(isinstance(x, int) for x in arr):
        logging.error("Error: arr must contain only integers.")
        raise ValueError("Error: arr must contain only integers.")

    if not isinstance(size, int):
        logging.error("Error: size must be an integer.")
        raise ValueError("Error: size must be an integer.")

    if not isinstance(index, int):
        logging.error("Error: index must be an integer.")
        raise ValueError("Error: index must be an integer.")

    if size != len(arr):
        logging.error("Error: size does not match the length of the array.")
        raise ValueError("Error: size does not match the length of the array.")

    if index < 0 or index >= size:
        logging.error(f"Error: Index {index} is out of bounds for array of size {size}.")
        raise ValueError(f"Error: Index {index} is out of bounds for array of size {size}.")

    return arr[index]


def main():
    """
    Reads an integer from the standard input and calls getValueFromArray with the id_sequence array, its size, and the read integer.
    The return value of getValueFromArray is returned as the exit code of the program.
    """

    parser = argparse.ArgumentParser(description="Get a value from an array by index.")
    parser.add_argument("index", type=int, help="The index to access in the array.")
    args = parser.parse_args()

    id_sequence = [10, 20, 30, 40, 50]
    size = len(id_sequence)
    index = args.index

    try:
        result = getValueFromArray(id_sequence, size, index)
        print(result)
        sys.exit(0)  # Indicate success and return the value

    except ValueError as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)  # Indicate an error


if __name__ == "__main__":
    main()

