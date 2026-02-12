import secrets
import sys

def float_to_string(float_value):
    """
    Converts a float to a string representation, handling potential edge cases.

    Args:
        float_value: The float value to convert.

    Returns:
        A string representation of the float.  Uses a safe and reliable formatting method.
    """
    return str(float_value)  # Simplest and most reliable for general use cases


def generate_secure_random_floats_as_strings():
    """
    Generates three cryptographically secure random floats and converts them to strings.

    Returns:
        A tuple containing three strings representing the random floats.
    """

    # Generate random floats using secrets.randbits and scaling.
    # This is more secure than using random.random() for security-sensitive applications.
    # The range is approximately 0.0 to 1.0 (exclusive of 1.0).  Adjust as needed.

    random_float_a = secrets.randbits(53) / (2**53)  # 53 bits for double-precision float
    random_float_b = secrets.randbits(53) / (2**53)
    random_float_c = secrets.randbits(53) / (2**53)

    str_a = float_to_string(random_float_a)
    str_b = float_to_string(random_float_b)
    str_c = float_to_string(random_float_c)

    return str_a, str_b, str_c


if __name__ == "__main__":
    str_a, str_b, str_c = generate_secure_random_floats_as_strings()

    print(f"String a: {str_a}")
    print(f"String b: {str_b}")
    print(f"String c: {str_c}")

