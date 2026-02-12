import secrets
import os
import stat
import logging  # Import the logging module

# Configure logging (replace with your actual logging setup)
logging.basicConfig(filename='random_data.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


def generate_and_write_random_data(filename="random_data.txt", num_bytes=64):
    """
    Generates cryptographically secure random bytes and writes them to a file.

    Args:
        filename (str, optional): The name of the file to write to.
                                   Defaults to "random_data.txt".
        num_bytes (int, optional): The number of random bytes to generate.
                                     Defaults to 64.
    """

    try:
        # Input validation: Sanitize filename to prevent directory traversal
        if not os.path.basename(filename) == filename:
            raise ValueError("Invalid filename: Filename must not contain path separators.")

        # Check if the file already exists
        filepath = os.path.abspath(filename)
        if os.path.exists(filepath):
            raise FileExistsError(f"File '{filename}' already exists.")


        # Generate cryptographically secure random bytes
        random_bytes = secrets.token_bytes(num_bytes)

        # Write the bytes to the file
        with open(filepath, "wb") as f:  # Use "wb" for writing binary data
            f.write(random_bytes)

        # Set file permissions to restrict access (e.g., only the owner can read/write)
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write

        print(f"Successfully wrote {num_bytes} random bytes to {filename}")

    except ValueError as e:
        print(f"Error: {e}")  # Specific error message for input validation
    except FileExistsError as e:
        print(f"Error: {e}")
    except OSError as e:
        print(f"Error writing to file: {e}") # Specific error message for file writing
        logging.exception("OSError occurred:") # Log the full exception
    except Exception as e:
        print("An unexpected error occurred.")  # Generic error message for other errors
        logging.exception("An unexpected error occurred:")  # Log the full exception


if __name__ == "__main__":
    # Example usage:
    generate_and_write_random_data()  # Writes 64 random bytes to random_data.txt
    generate_and_write_random_data("my_random_data.bin", 128)  # Writes 128 random bytes to my_random_data.bin

    # Example of an invalid filename (will raise an error)
    # generate_and_write_random_data("../sensitive_data.txt")

