import secrets
import os
import struct
import stat

def generate_secure_float():
    """Generates a cryptographically secure random float between 0.0 and 1.0."""
    random_bytes = secrets.token_bytes(8)  # 8 bytes = 64 bits
    # Convert bytes to a float.  The exact method depends on your needs.
    # This example uses struct.unpack to interpret the bytes as a double-precision float.
    float_value = struct.unpack('d', random_bytes)[0]
    # Scale to the range [0.0, 1.0)
    return abs(float_value % 1.0)  # Ensure positive and within range


def generate_and_write_random_floats(filename="random_floats.txt", safe_directory="random_data"):
    """
    Generates 3 random floats, converts them to strings, concatenates them,
    and writes the resulting string to a file in a safe directory.  Uses secrets module for
    cryptographically secure random number generation.  Includes security
    measures to prevent path traversal and set restrictive file permissions.

    Args:
        filename (str, optional): The name of the file to write to.
                                   Defaults to "random_floats.txt".
        safe_directory (str, optional): The directory to store the file in.
                                        Defaults to "random_data".
    """

    # Ensure the safe directory exists
    if not os.path.exists(safe_directory):
        try:
            os.makedirs(safe_directory)
        except OSError as e:
            print(f"Error creating safe directory: {e}")
            return

    # Sanitize the filename
    base_filename = os.path.basename(filename)
    safe_filename = os.path.join(safe_directory, base_filename)

    try:
        # Generate 3 cryptographically secure random floats
        random_floats = [generate_secure_float() for _ in range(3)]

        # Convert floats to strings
        float_strings = [str(f) for f in random_floats]

        # Concatenate the strings with a separator
        concatenated_string = ",".join(float_strings)

        # Write the string to the file
        with open(safe_filename, "w") as f:
            f.write(concatenated_string)

        # Set file permissions to read/write for the owner only
        os.chmod(safe_filename, stat.S_IRUSR | stat.S_IWUSR)

        print(f"Successfully wrote random floats to {safe_filename}")

    except OSError as e:
        print(f"An error occurred: {e}")
    except IOError as e:
        print(f"File I/O error: {e}")


if __name__ == "__main__":
    # Example usage:
    generate_and_write_random_floats()  # Writes to random_data/random_floats.txt
    generate_and_write_random_floats("../my_random_data.txt") # Writes to random_data/my_random_data.txt

