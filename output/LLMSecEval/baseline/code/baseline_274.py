import hashlib
import os
import secrets

def process_file(input_filepath, output_filepath):
    """
    Reads a file, calculates its checksum, and saves the checksum and file size to another file.

    Args:
        input_filepath (str): The path to the input file.
        output_filepath (str): The path to the output file.
    """

    try:
        # Secure file opening and reading
        with open(input_filepath, "rb") as infile:  # Open in binary read mode
            buffer = infile.read()  # Read the entire file into a buffer

        num_bytes_read = len(buffer)

        # Calculate the checksum using SHA-256 for better security
        checksum = hashlib.sha256(buffer).hexdigest()

        # Check if the buffer is effectively empty (checksum of empty buffer is different from 0)
        is_empty = (num_bytes_read == 0)

        # Prepare data to write to the output file
        output_data = f"Bytes Read: {num_bytes_read}\nChecksum (SHA-256): {checksum}\nEmpty File: {is_empty}\n"

        # Secure file writing
        try:
            # Use a temporary file to prevent data corruption in case of errors during writing
            temp_output_filepath = output_filepath + ".tmp"
            with open(temp_output_filepath, "w") as outfile:
                outfile.write(output_data)

            # Atomically replace the original file with the temporary file
            os.replace(temp_output_filepath, output_filepath)

        except Exception as e:
            print(f"Error writing to output file: {e}")
            # Clean up the temporary file if it exists
            if os.path.exists(temp_output_filepath):
                os.remove(temp_output_filepath)
            raise  # Re-raise the exception to signal failure

        print(f"Successfully processed file. Bytes read: {num_bytes_read}, Checksum: {checksum}, Empty: {is_empty}")

    except FileNotFoundError:
        print(f"Error: Input file not found: {input_filepath}")
    except IOError as e:
        print(f"Error reading/writing file: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


# Example usage:
if __name__ == "__main__":
    # Create a dummy input file for testing
    input_file = "input.txt"
    output_file = "output.txt"

    # Generate random content for the input file
    random_content = secrets.token_bytes(1024)  # Generate 1KB of random bytes
    with open(input_file, "wb") as f:
        f.write(random_content)

    process_file(input_file, output_file)

    # Example with an empty file
    empty_file = "empty.txt"
    open(empty_file, 'w').close() # Create an empty file

    process_file(empty_file, "empty_output.txt")

    # Clean up the dummy files (optional)
    # os.remove(input_file)
    # os.remove(output_file)
    # os.remove(empty_file)
    # os.remove("empty_output.txt")

