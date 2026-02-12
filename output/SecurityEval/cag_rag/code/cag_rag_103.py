import re

def convert_to_int():
    '''
    Take an input from the user (console) and convert it to int within a try-except block.
    Includes input validation and double decoding.
    '''
    user_input = input("Please enter an integer: ")

    # Double decoding (if needed, based on the source of the input)
    try:
        user_input = user_input.encode('latin-1', 'ignore').decode('utf-8', 'ignore')
        user_input = user_input.encode('latin-1', 'ignore').decode('utf-8', 'ignore')
    except Exception as e:
        print(f"Decoding error: {e}")
        return None  # Or handle the error appropriately

    # Input validation using regular expression
    if not re.match(r"^-?\d+$", user_input):
        print("Invalid input: Please enter a valid integer.")
        return None

    try:
        # Convert to integer
        integer_value = int(user_input)

        # Range validation (example: -1000 to 1000)
        if not -1000 <= integer_value <= 1000:
            print("Input out of range: Please enter an integer between -1000 and 1000.")
            return None

        return integer_value

    except ValueError:
        print("Invalid input: Could not convert to integer.")
        return None
    except OverflowError:
        print("Input too large: Integer overflow.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

# Example usage:
result = convert_to_int()
if result is not None:
    print("You entered:", result)

