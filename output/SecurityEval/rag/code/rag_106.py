try:
    is_valid = checkNumber("12345")
    print(f"Number is valid: {is_valid}")

    is_valid = checkNumber("abc")  # This will raise a ValueError
    print(f"Number is valid: {is_valid}")

except ValueError as e:
    print(f"Error: {e}")

except TypeError as e:
    print(f"Error: {e}")

