import os
import signal
import logging
import psutil  # Optional, for more robust process management
import os  # Import os for getuid

# Configure logging (optional, but recommended for security)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def killProcess(processID: int) -> None:
    """
    Kill the process with the given processID.  Uses a safe method to send the signal.

    Args:
        processID: The ID of the process to kill.  Must be an integer.

    Raises:
        TypeError: If processID is not an integer.
        ValueError: If processID is not a positive integer.
        PermissionError: If the user does not have permission to kill the process.
        ProcessLookupError: If the process does not exist.
        OSError: For other errors during process termination.
    """

    # Input validation:  Check if processID is an integer and positive.
    if not isinstance(processID, int):
        logging.error(f"Invalid processID: {processID}.  Must be an integer.")
        raise TypeError("processID must be an integer")

    if processID <= 0:
        logging.error(f"Invalid processID: {processID}.  Must be a positive integer.")
        raise ValueError("processID must be a positive integer")

    try:
        # Optional: Use psutil to check if the process exists before attempting to kill it.
        if psutil.pid_exists(processID):
            try:
                os.kill(processID, signal.SIGTERM)
                logging.info(f"Process {processID} terminated (SIGTERM) by user {os.getuid()}.")
            except OSError as e:
                logging.warning(f"SIGTERM failed for process {processID}: {e}.  Trying SIGKILL.")
                try:
                    os.kill(processID, signal.SIGKILL)
                    logging.info(f"Process {processID} terminated (SIGKILL) by user {os.getuid()}.")
                except OSError as e2:
                    logging.error(f"SIGKILL failed for process {processID}: {e2}")
                    raise  # Re-raise the exception
        else:
            logging.warning(f"Process {processID} does not exist.")
            raise ProcessLookupError(f"Process {processID} does not exist.")

    except (PermissionError, ProcessLookupError, OSError) as e:
        logging.error(f"Error killing process {processID}: {e}")
        raise  # Re-raise the exception

# Example usage (for testing - replace with your actual process ID):
if __name__ == '__main__':
    try:
        # Replace with a valid process ID for testing.  Be careful!
        # This example tries to kill a process with ID 12345.  Make sure this is safe to do!
        killProcess(12345)
    except (TypeError, ValueError) as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

