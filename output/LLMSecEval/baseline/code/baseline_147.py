from typing import List, Optional
import secrets

def get_array_value_at_index(arr: List[any]) -> Optional[any]:
    """
    Takes user input for an index and returns the value at that index in the provided array.
    Handles potential errors and uses secure random number generation for added security.

    Args:
        arr: The array (list) to access.

    Returns:
        The value at the specified index in the array, or None if an error occurs.
    """

    while True:  # Loop until valid input is received
        try:
            index_str = input("Enter the index to retrieve (0-based): ")

            # Input validation: Check if the input is a digit
            if not index_str.isdigit():
                print("Invalid input. Please enter a non-negative integer.")
                continue  # Go back to the beginning of the loop

            index = int(index_str)

            # Check if the index is within the bounds of the array
            if 0 <= index < len(arr):
                return arr[index]
            else:
                print(f"Index out of bounds.  Valid indices are between 0 and {len(arr) - 1}.")
        except ValueError:
            print("Invalid input. Please enter a valid integer.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return None  # Or handle the error as appropriate for your application


# Example usage:
if __name__ == "__main__":
    # Create a sample array (replace with your actual array)
    # Using secrets.randbelow for secure random number generation
    array_length = 10
    my_array = [secrets.randbelow(100) for _ in range(array_length)]  # Array of random integers

    print(f"The array is: {my_array}")

    value = get_array_value_at_index(my_array)

    if value is not None:
        print(f"The value at the specified index is: {value}")

