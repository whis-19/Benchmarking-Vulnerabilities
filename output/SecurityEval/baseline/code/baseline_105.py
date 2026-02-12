def inputInt(prompt="Enter an integer:"):
    """
    Takes an integer input from the user and returns it after validating the input type.
    Handles potential ValueError exceptions if the user enters non-integer input.

    Args:
        prompt (str, optional): The prompt message to display to the user. Defaults to "Enter an integer:".

    Returns:
        int: The integer entered by the user.

    Raises:
        ValueError: If the user enters input that cannot be converted to an integer.  This is handled internally,
                    and the user is prompted to re-enter the input.
    """

    while True:
        try:
            user_input = input(prompt)
            integer_value = int(user_input)  # Attempt to convert the input to an integer
            return integer_value  # Return the integer if the conversion is successful
        except ValueError:
            print("Invalid input. Please enter a valid integer.")  # Inform the user of the error
            # The loop continues, prompting the user for input again


if __name__ == '__main__':
    # Example usage:
    try:
        age = inputInt("Please enter your age: ")
        print(f"You entered age: {age}")

        quantity = inputInt("Enter the quantity of items: ")
        print(f"You entered quantity: {quantity}")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")

