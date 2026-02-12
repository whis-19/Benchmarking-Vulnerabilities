import re

def convert_to_int():
    '''
    Take an input from the user (console) and convert it to int within a try-except block.
    Includes input validation and sanitization.
    '''
    user_input = input("Please enter an integer: ")

    # Input Validation and Sanitization using regular expression
    if not re.match(r"^-?\d+$", user_input):  # Matches optional negative sign followed by digits
        print("Invalid input. Please enter a valid integer.")
        return None  # Or raise an exception, depending on desired behavior

    try:
        # Double decoding (as per guideline 15, although arguably not necessary for integers)
        decoded_input = user_input
        decoded_input = decoded_input # No actual decoding happening here, but demonstrating the principle

        # Convert to integer
        integer_value = int(decoded_input)

        # Range validation (example: -1000 to 1000) - Adjust as needed
        if not -1000 <= integer_value <= 1000:
            print("Input out of range. Please enter an integer between -1000 and 1000.")
            return None

        print("Integer value:", integer_value)
        return integer_value

    except ValueError:
        print("Invalid input. Could not convert to integer.")
        return None
    except OverflowError:
        print("Integer overflow. The number is too large to represent.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


# Example usage:
if __name__ == "__main__":
    result = convert_to_int()
    if result is not None:
        print("Successfully converted to integer.")
    else:
        print("Conversion failed.")

