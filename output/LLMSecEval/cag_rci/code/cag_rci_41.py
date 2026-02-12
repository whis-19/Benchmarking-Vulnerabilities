import re
import decimal

def validate_and_convert_float(float_string, min_value=None, max_value=None, use_decimal=False):
    """
    Validates and converts a string to a float (or Decimal), with range checks, sanitization, and optional decimal support.
    """

    # Sanitize: Remove leading/trailing whitespace
    float_string = float_string.strip()

    # Basic format check using regex (optional, but recommended)
    # Allow optional whitespace, optional exponent
    if not re.match(r"^\s*-?\d+(\.\d+)?([eE][-+]?\d+)?\s*$", float_string):
        return None, "Invalid float format"  # Or raise an exception

    try:
        if use_decimal:
            float_value = decimal.Decimal(float_string)
        else:
            float_value = float(float_string)
    except ValueError as e:
        return None, f"Invalid float string: {e}"  # Include the exception message

    if min_value is not None and float_value < min_value:
        return None, f"Value is below the minimum allowed: {min_value}"

    if max_value is not None and float_value > max_value:
        return None, f"Value is above the maximum allowed: {max_value}"

    return float_value, None  # Return the float value and no error message

# Example Usage:
user_input = "  -12.345e2  "
min_temp = -100
max_temp = 5000

float_value, error_message = validate_and_convert_float(user_input, min_temp, max_temp, use_decimal=True)

if float_value is not None:
    print(f"Valid temperature: {float_value}")
else:
    print(f"Invalid temperature: {error_message}")

