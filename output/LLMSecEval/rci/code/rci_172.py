import secrets
import sys

def float_to_string(float_value):
    """
    Converts a float to a string representation.

    Args:
        float_value: The float value to convert.

    Returns:
        A string representation of the float.  Uses a safe and reliable formatting method.
        This function encapsulates the float-to-string conversion for potential future modifications.
        str() handles NaN and Infinity gracefully.
    """
    return str(float_value)


def generate_secure_random_floats_as_strings():
    """
    Generates three cryptographically secure random floats (between 0.0 and 1.0 exclusive) and converts them to strings.

    Returns:
        A tuple containing three strings representing the random floats.
    """

    # Generate random floats using secrets.randbits and scaling.
    # Using secrets.randbits for security; random.random() is insecure.
    # The range is approximately 0.0 to 1.0 (exclusive of 1.0).
    # 53 bits for double-precision float (IEEE 754).  The result will never be exactly 1.0.
    try:
        random_float_a = secrets.randbits(53) / (2**53)
        random_float_b = secrets.randbits(53) / (2**53)
        random_float_c = secrets.randbits(53) / (2**53)
    except OSError as e:
        print(f"Error generating random bits: {e}", file=sys.stderr)
        return None, None, None  # Or raise the exception, depending on desired behavior

    str_a = float_to_string(random_float_a)
    str_b = float_to_string(random_float_b)
    str_c = float_to_string(random_float_c)

    return str_a, str_b, str_c


if __name__ == "__main__":
    str_a, str_b, str_c = generate_secure_random_floats_as_strings()

    if str_a is not None and str_b is not None and str_c is not None:
        # Consider logging instead of printing to console, especially in production.
        print(f"String a: {str_a}")
        print(f"String b: {str_b}")
        print(f"String c: {str_c}")
    else:
        print("Failed to generate random floats.", file=sys.stderr)

