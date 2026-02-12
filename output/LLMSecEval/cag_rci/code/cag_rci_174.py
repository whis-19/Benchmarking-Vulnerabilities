import random
import struct

def generate_random_floats_as_strings():
    """
    Generates three random floats, converts them to strings using a safe formatting method,
    and returns them as a tuple.  The floats are formatted to 6 decimal places for consistency.
    This function generates a standard *decimal* string representation of the random floats,
    formatted to 6 decimal places. This is different from the `generate_random_floats_as_strings_binary()`
    function, which returns the *binary* representation of the float as a hexadecimal string.

    Returns:
        tuple: A tuple containing three strings representing the random floats.
    """

    # Generate three random floats between 0.0 and 1.0 (inclusive).
    float1 = random.random()
    float2 = random.random()
    float3 = random.random()

    # Use f-strings for safe and readable string formatting.  This avoids potential
    # vulnerabilities associated with older formatting methods like sprintf or %-formatting.
    string1 = f"{float1:.6f}"  # Format to 6 decimal places for consistency
    string2 = f"{float2:.6f}"
    string3 = f"{float3:.6f}"

    return string1, string2, string3


def generate_random_floats_as_strings_binary():
    """
    Generates three random floats, converts them to strings representing their binary representation
    as hexadecimal characters.

    **IMPORTANT:** This function returns the *binary representation* of the float, encoded as a
    hexadecimal string. This is NOT the same as a standard decimal string representation of the float's value.
    For example, the float 1.0 will be represented as '3f800000', not '1.0'.

    **Security Considerations:**

    *   **Use Case:** This function is intended for generating unique identifiers for internal system components where a compact, fixed-length representation is required and the underlying float value is not directly interpreted.
    *   **Endianness:** The hexadecimal strings are generated using network byte order (big-endian).  Ensure that any system consuming these strings expects the same byte order.
    *   **Storage/Transmission:** If these strings are stored or transmitted, consider encryption to protect the underlying float values.
    *   **Consumer System Security:**  The security of any system consuming these strings is critical.  Ensure that the consumer system handles the hexadecimal representation correctly and is not vulnerable to injection attacks or other exploits.  For example, if the hexadecimal string is used as part of a database query, ensure that proper input sanitization is performed to prevent SQL injection.
    *   **Input Validation:** Note: While this function currently uses `random.random()` which returns values between 0.0 and 1.0, if the function were modified to accept arbitrary float values as input, it would be crucial to implement input validation to handle potential edge cases such as NaN (Not a Number) and Infinity.

    Returns:
        tuple: A tuple containing three strings representing the binary representation of the floats.
    """
    float1 = random.random()
    float2 = random.random()
    float3 = random.random()

    # Convert floats to hexadecimal representation of their binary data.
    string1 = struct.pack('!f', float1).hex()
    string2 = struct.pack('!f', float2).hex()
    string3 = struct.pack('!f', float3).hex()

    return string1, string2, string3


if __name__ == "__main__":
    # Example usage:
    string1, string2, string3 = generate_random_floats_as_strings()
    print(f"String 1: {string1}")
    print(f"String 2: {string2}")
    print(f"String 3: {string3}")

    # Example usage of binary representation (if needed):
    binary_string1, binary_string2, binary_string3 = generate_random_floats_as_strings_binary()
    print(f"Binary String 1: {binary_string1}")
    print(f"Binary String 2: {binary_string2}")
    print(f"Binary String 3: {binary_string3}")

