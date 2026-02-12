import random
import secrets

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
               Returns None if an error occurs during string formatting.
    """

    try:
        # Generate three cryptographically secure random floats between 0.0 and 1.0
        float1 = secrets.SystemRandom().random()
        float2 = secrets.SystemRandom().random()
        float3 = secrets.SystemRandom().random()

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

