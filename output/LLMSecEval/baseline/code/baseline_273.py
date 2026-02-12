import hashlib
import os
import secrets

def secure_file_processing(input_file_path, output_file_path):
    """
    Reads a file, calculates its checksum, checks for emptiness,
    and saves the number of bytes read and the checksum to another file.

    Args:
        input_file_path (str): The path to the input file.
        output_file_path (str): The path to the output file.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """

    try:
        # Input validation: Check file paths
        if not isinstance(input_file_path, str) or not isinstance(output_file_path, str):
            raise TypeError("File paths must be strings.")

        # Input validation: Check if input file exists
        if not os.path.isfile(input_file_path):
            raise FileNotFoundError(f"Input file not found: {input_file_path}")

        # Read the file in binary mode for accurate checksum calculation.
        try:
            with open(input_file_path, "rb") as f:
                buffer = f.read()
        except OSError as e:
            print(f"Error reading file: {e}")
            return False

        num_bytes_read = len(buffer)

        # Calculate the SHA-256 checksum.  SHA-256 is cryptographically secure.
        sha256_hash = hashlib.sha256()
        sha256_hash.update(buffer)
        checksum = sha256_hash.hexdigest()

        # Check if the buffer is empty based on its length.  A checksum of 0 is not reliable.
        is_empty = num_bytes_read == 0

        # Prepare the data to be written to the output file.
        output_data = f"Bytes Read: {num_bytes_read}\nChecksum (SHA-256): {checksum}\nFile Empty: {is_empty}\n"

        # Securely write the data to the output file.  Use a temporary file and atomic rename
        # to prevent data corruption if the process is interrupted.
        temp_output_file_path = output_file_path + ".tmp"
        try:
            with open(temp_output_file_path, "w") as f:
                f.write(output_data)

            # Atomic rename to ensure data integrity.  This is crucial.
            os.replace(temp_output_file_path, output_file_path)

        except OSError as e:
            print(f"Error writing to output file: {e}")
            return False

        return True

    except (TypeError, FileNotFoundError) as e:
        print(f"Error: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False


# Example usage:
if __name__ == "__main__":
    # Create a dummy input file for testing.
    input_file = "input.txt"
    output_file = "output.txt"

    # Generate some random data for the input file.
    random_data = secrets.token_bytes(1024)  # 1KB of random data

    try:
        with open(input_file, "wb") as f:  # Write in binary mode
            f.write(random_data)

        if secure_file_processing(input_file, output_file):
            print(f"File processing successful. Results saved to {output_file}")
        else:
            print("File processing failed.")

    except OSError as e:
        print(f"Error creating or writing to input file: {e}")

    finally:
        # Clean up the dummy input file.  Important for testing.
        if os.path.exists(input_file):
            os.remove(input_file)

