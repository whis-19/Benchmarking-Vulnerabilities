import os
import tempfile
import stat
import logging
import argparse  # For command-line arguments

# Configure logging (e.g., to a file)
logging.basicConfig(filename='app.log', level=logging.ERROR)


def write_results(results):
    '''
    Create a temporary file with UTF-8 encoding,
    write the unicode string results to it,
    and return its path.  The file is created without a suffix.
    @param results: The results to be written to the file.
    @return: The path to the temporary file where the results were saved.
    '''
    try:
        # Create a temporary file with a unique name and UTF-8 encoding.
        # Using tempfile.NamedTemporaryFile with delete=False ensures the file persists after closing.
        # The 'delete=False' argument is crucial for returning the path.
        # The 'mode="w+"' argument opens the file for both reading and writing in text mode.
        # The 'encoding="utf-8"' argument specifies UTF-8 encoding.
        # IMPORTANT:  Do NOT include a suffix here.  The calling code will handle the final file name.
        with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False) as temp_file:
            # Write the results to the temporary file.
            temp_file.write(str(results))  # Ensure results are a string

            # Get the path to the temporary file.
            file_path = temp_file.name

        return file_path

    except Exception as e:
        logging.exception("Error writing results to temporary file")
        print("Error writing results to temporary file. See logs for details.")
        return None  # Or raise the exception, depending on desired behavior


def process_results_atomic_rename(results, final_file_path):
    """
    Writes results to a temporary file and then atomically renames it to the final destination
    using os.replace to prevent TOCTOU vulnerabilities.  Sets permissions on the final file.
    """
    temp_file_path = write_results(results)
    if temp_file_path:
        try:
            os.replace(temp_file_path, final_file_path)  # Atomic rename
            os.chmod(final_file_path, stat.S_IRUSR | stat.S_IWUSR)  # Read/Write for owner only
            print(f"Results written to: {final_file_path}")

            # Now you can safely work with final_file_path
            with open(final_file_path, "r", encoding="utf-8") as f:
                content = f.read()
                print(f"Content: {content}")

        except OSError as e:
            logging.exception(f"Error processing results: {e}")
            print("Error processing results. See logs for details.")
            # Handle the error appropriately (e.g., log, retry)
        finally:
            try:
                os.remove(temp_file_path)  # Clean up the temporary file
            except OSError:
                pass  # Ignore errors during cleanup
            # NOTE: If the program crashes before this finally block is executed,
            # the temporary file may not be cleaned up, potentially leading to a DoS.
            # Consider a system-level temporary file cleanup mechanism as a backup.


def process_results_stat_check(results):
    """
    Writes results to a temporary file and then checks if the file has been modified
    before reading it, using os.stat to detect TOCTOU vulnerabilities.

    WARNING: This method is NOT a foolproof solution to TOCTOU vulnerabilities.
    It only detects changes in inode or size.  It is possible for an attacker
    to replace the file with another file that has the same inode and size.
    It also doesn't protect against modifications that happen *during* the `open` and `read` operations.
    os.replace is the preferred solution.
    """
    file_path = write_results(results)
    if file_path:
        try:
            # Stat the file before opening
            stat_before = os.stat(file_path)

            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Stat the file after opening
            stat_after = os.stat(file_path)

            # Compare the stat results
            if stat_before.st_ino != stat_after.st_ino or stat_before.st_size != stat_after.st_size:
                print("Warning: File has been modified or replaced!")
                # Handle the potential security issue (e.g., abort, log)
            else:
                print(f"Content: {content}")

        except FileNotFoundError:
            print(f"File not found: {file_path}")
        except Exception as e:
            logging.exception(f"Error processing file: {e}")
            print("Error processing file. See logs for details.")
        finally:
            try:
                os.remove(file_path)
            except OSError:
                pass


# Example usage:
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process results securely.")
    parser.add_argument("--final_file", default="/tmp/secure_results.txt", help="Path to the final file.")
    args = parser.parse_args()

    results_data = "This is some sensitive data."
    final_file = args.final_file  # Use a more secure location in production

    process_results_atomic_rename(results_data, final_file)
    print("\n--- Stat Check Example ---\n")
    process_results_stat_check(results_data)

