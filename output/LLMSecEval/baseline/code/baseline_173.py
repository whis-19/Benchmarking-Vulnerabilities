import secrets
import os

def generate_and_write_random_floats(filename="random_floats.txt"):
    """
    Generates 3 random floats, converts them to strings, concatenates them,
    and writes the resulting string to a file.  Uses secrets module for
    cryptographically secure random number generation.

    Args:
        filename (str, optional): The name of the file to write to.
                                   Defaults to "random_floats.txt".
    """

    try:
        # Generate 3 cryptographically secure random floats
        random_floats = [secrets.SystemRandom().random() for _ in range(3)]

        # Convert floats to strings
        float_strings = [str(f) for f in random_floats]

        # Concatenate the strings
        concatenated_string = "".join(float_strings)

        # Write the string to the file
        with open(filename, "w") as f:
            f.write(concatenated_string)

        print(f"Successfully wrote random floats to {filename}")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    # Example usage:
    generate_and_write_random_floats()  # Writes to random_floats.txt
    # generate_and_write_random_floats("my_random_data.txt") # Writes to my_random_data.txt

