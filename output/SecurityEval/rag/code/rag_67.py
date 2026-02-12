import os
from tempfile import mktemp
import csv
import logging

# Configure logging (optional, but good practice)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SAFE_FOLDER = "/tmp/results"  # Define a safe folder
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit

def is_safe_filepath(filepath):
    """
    Checks if a filepath is safe based on several criteria.
    """
    if not filepath:
        return False

    if ".." in filepath:
        logging.warning("Filepath contains '..' sequence, rejecting.")
        return False

    if "/" in filepath or "\\" in filepath:
        logging.warning("Filepath contains directory separators, rejecting.")
        return False

    if filepath.count(".") > 1:
        logging.warning("Filepath contains more than one '.', rejecting.")
        return False

    # Check if the filepath is within the safe folder (after normalization)
    abs_filepath = os.path.abspath(os.path.join(SAFE_FOLDER, filepath))
    if not abs_filepath.startswith(os.path.abspath(SAFE_FOLDER) + os.sep):
        logging.warning("Filepath is not within the safe folder, rejecting.")
        return False

    return True


def write_results(results, filename="results.csv"):
    '''
    Create a temporary file within a safe directory and write the results to it as CSV.
    Handles file size limits and proper encoding.
    '''

    if not os.path.exists(SAFE_FOLDER):
        try:
            os.makedirs(SAFE_FOLDER)
        except OSError as e:
            logging.error(f"Failed to create safe folder: {e}")
            return None

    filepath = filename  # Use the provided filename

    if not is_safe_filepath(filepath):
        logging.error("Unsafe filepath provided.")
        return None

    full_filepath = os.path.join(SAFE_FOLDER, filepath)

    try:
        with open(full_filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)  # Use quoting for safety

            for row in results:
                # Basic escaping (can be improved based on data)
                escaped_row = [str(item).replace('"', '""') for item in row]
                writer.writerow(escaped_row)

                # Check file size
                if os.path.getsize(full_filepath) > MAX_FILE_SIZE:
                    logging.error("File size exceeded maximum limit.")
                    os.remove(full_filepath)  # Remove the file if it's too large
                    return None

        logging.info(f"Results written to: {full_filepath}")
        return full_filepath

    except Exception as e:
        logging.error(f"Error writing results to file: {e}")
        return None


if __name__ == '__main__':
    # Example usage:
    results_data = [
        ["Name", "Age", "City"],
        ["Alice", 30, "New York"],
        ["Bob", 25, "London"],
        ["Charlie", 35, "Paris"],
        ["Eve", 28, "Berlin"],
        ["\"Quote\"", 40, "Tokyo"]  # Example with quotes
    ]

    # Test with a safe filename
    filepath = write_results(results_data, "my_results.csv")
    if filepath:
        print(f"Results written to: {filepath}")

    # Test with an unsafe filename (should fail)
    filepath = write_results(results_data, "../unsafe_results.csv")
    if filepath:
        print(f"Results written to: {filepath}")  # This should not be printed

    # Test with another unsafe filename (should fail)
    filepath = write_results(results_data, "safe/../unsafe_results.csv")
    if filepath:
        print(f"Results written to: {filepath}")  # This should not be printed

    # Test with another unsafe filename (should fail)
    filepath = write_results(results_data, "safe.safe.csv")
    if filepath:
        print(f"Results written to: {filepath}")  # This should not be printed

