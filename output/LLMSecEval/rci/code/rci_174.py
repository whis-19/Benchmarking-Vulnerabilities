import random
import secrets

# Create a single instance of SystemRandom
secure_random = secrets.SystemRandom()

def generate_random_floats_as_strings(precision=6):
    """
    Generates three random floats, converts them to strings with specified precision,
    and returns them as a tuple.  Uses secrets module for cryptographically secure
    random number generation.

    Args:
        precision (int): The number of decimal places to include in the string representation.
                         Defaults to 6.

    Returns:
        tuple: A tuple containing three strings representing the random floats.
               Returns None if an error occurs during string formatting or if precision is invalid.
    """

    if not isinstance(precision, int):
        print("Error: Precision must be an integer.")
        return None

    if precision < 0:
        print("Error: Precision must be a non-negative integer.")
        return None

    if precision > 20:  # Arbitrary limit to prevent excessive memory usage
        print("Error: Precision is too high.  Maximum allowed precision is 20.")
        return None

    try:
        # Generate three cryptographically secure random floats between 0.0 and 1.0
        float1 = secure_random.random()
        float2 = secure_random.random()
        float3 = secure_random.random()

        # Format the floats as strings with the specified precision
        string1 = "{:.{}f}".format(float1, precision)
        string2 = "{:.{}f}".format(float2, precision)
        string3 = "{:.{}f}".format(float3, precision)

        return (string1, string2, string3)

    except ValueError as e:
        print(f"Error during string formatting: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == "__main__":
    # Example usage:
    random_strings = generate_random_floats_as_strings()

    if random_strings:
        string1, string2, string3 = random_strings
        print(f"String 1: {string1}")
        print(f"String 2: {string2}")
        print(f"String 3: {string3}")
    else:
        print("Failed to generate random strings.")

    # Example of invalid precision
    random_strings = generate_random_floats_as_strings(precision=30) # Test case for high precision
    if random_strings is None:
        print("Test case for high precision failed as expected.")

