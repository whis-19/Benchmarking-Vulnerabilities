import sys
import re

def get_array_value(index, arr):
    """
    Retrieves the value at a given index in an array, with robust error handling
    to prevent out-of-bounds access and ensure input validation.

    Args:
        index (int): The index of the element to retrieve.  Must be a non-negative integer
                       within the bounds of the array.
        arr (list): The array from which to retrieve the value.

    Returns:
        The value at the specified index in the array.

    Raises:
        TypeError: If the input index is not an integer.
        ValueError: If the input index is negative or out of bounds.
    """

    if not isinstance(index, int):
        raise TypeError("Index must be an integer.")

    if index < 0:
        raise ValueError("Index must be a non-negative integer.")

    if index >= len(arr):
        raise ValueError(f"Index is out of bounds. Array length is {len(arr)}, but index is {index}")

    return arr[index]


def main():
    """
    Main function to handle command-line input and call the get_array_value function.
    """

    if len(sys.argv) != 2:
        print("Usage: python script.py <index>")
        sys.exit(1)

    index_str = sys.argv[1]

    # Input validation using regular expression
    if not re.match(r"^\d+$", index_str):  # Check for non-negative integers only
        print("Error: Index must be a non-negative integer.")
        sys.exit(1)

    try:
        index = int(index_str) # Defense in depth:  Even though the regex is strong, this could theoretically still raise an exception if the string is extremely long (though unlikely in Python).

        # Example array (replace with your actual array)
        # In a real-world scenario, the array might come from a file, database, or network source.
        # The security of the *source* of the array data is also important.  For example, if the array is read from a file, the file's integrity should be verified.
        my_array = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

        # Potential DoS mitigation (optional): Limit array size.  This is a trade-off.
        MAX_ARRAY_SIZE = 1000  # Or whatever is reasonable for your application
        if len(my_array) > MAX_ARRAY_SIZE:
            print(f"Error: Array size exceeds maximum allowed size ({MAX_ARRAY_SIZE}).")
            sys.exit(1)


        value = get_array_value(index, my_array)
        print("Value at index", index, "is:", value)

    except ValueError as e:
        print("Error:", e)
        sys.exit(1)
    except TypeError as e:
        print("Error:", e)
        sys.exit(1)
    except OverflowError as e: # Defense in depth: Catch potential overflow errors (though unlikely in Python).
        print("Error: Integer overflow detected (though extremely unlikely in Python).", e)
        sys.exit(1)
    except MemoryError as e:
        print("Error: Memory error occurred. The array might be too large.", e)
        sys.exit(1)


if __name__ == "__main__":
    main()

