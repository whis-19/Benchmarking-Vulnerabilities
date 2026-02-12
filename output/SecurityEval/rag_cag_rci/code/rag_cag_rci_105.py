import re

def inputInt(min_value=None, max_value=None, allowed_values=None):
    '''
    Take an int input and return it after checking type and validating against specified constraints.

    Security Considerations:
    - Input Validation:  Validates that the input is an integer and optionally within a specified range or from a set of allowed values.
    - Error Handling:  Handles potential ValueError exceptions during type conversion.
    - Range Limiting:  Allows specifying minimum and maximum acceptable values.
    - Allowed Values:  Allows specifying a set of acceptable values.
    - Regular Expression Validation: Uses a regular expression to ensure the input string only contains digits.

    Args:
        min_value (int, optional): The minimum acceptable integer value. Defaults to None.
        max_value (int, optional): The maximum acceptable integer value. Defaults to None.
        allowed_values (list, optional): A list of allowed integer values. Defaults to None.

    Returns:
        int: The validated integer input.

    Raises:
        ValueError: If the input is not a valid integer, is outside the specified range, or is not in the allowed values.
    '''

    while True:
        try:
            user_input = input("Please enter an integer: ")

            # Validate input using regular expression to allow only digits
            if not re.match(r"^-?\d+$", user_input):
                raise ValueError("Invalid input: Input must be an integer.")

            num = int(user_input)

            # Validate against allowed values
            if allowed_values is not None and num not in allowed_values:
                raise ValueError(f"Invalid input: Input must be one of the following: {allowed_values}")

            # Validate against minimum value
            if min_value is not None and num < min_value:
                raise ValueError(f"Invalid input: Input must be greater than or equal to {min_value}")

            # Validate against maximum value
            if max_value is not None and num > max_value:
                raise ValueError(f"Invalid input: Input must be less than or equal to {max_value}")

            return num

        except ValueError as e:
            print(f"Error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}") # Catch other potential errors
            
# Example Usage (with validation):
if __name__ == '__main__':
    try:
        age = inputInt(min_value=0, max_value=120)
        print(f"Age entered: {age}")

        # Example with allowed values
        choice = inputInt(allowed_values=[1, 2, 3])
        print(f"Choice entered: {choice}")

        # Example without any constraints
        number = inputInt()
        print(f"Number entered: {number}")

    except ValueError as e:
        print(f"Error during input: {e}")

