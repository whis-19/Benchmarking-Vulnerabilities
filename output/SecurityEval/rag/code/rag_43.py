import os
import signal
import logging

# Configure logging (optional, but recommended for security auditing)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def killProcess(processID):
    '''
    Kill the process with the given processID.  Uses a safe method to avoid command injection.
    '''

    # Validate processID is an integer
    if not isinstance(processID, int):
        logging.error(f"Invalid processID: {processID}.  Must be an integer.")
        raise ValueError("processID must be an integer.")

    # Validate processID is a positive integer
    if processID <= 0:
        logging.error(f"Invalid processID: {processID}.  Must be a positive integer.")
        raise ValueError("processID must be a positive integer.")

    try:
        # Use the signal module directly.  This avoids shell injection vulnerabilities.
        os.kill(processID, signal.SIGTERM)  # Or signal.SIGKILL if SIGTERM doesn't work
        logging.info(f"Process {processID} terminated with SIGTERM.")

    except ProcessLookupError:
        logging.warning(f"Process {processID} not found.")
        print(f"Process {processID} not found.") # Optional: Inform the user.

    except PermissionError:
        logging.error(f"Permission denied to kill process {processID}.")
        print(f"Permission denied to kill process {processID}.") # Optional: Inform the user.
        raise  # Re-raise the exception to signal the failure to the caller.

    except Exception as e:
        logging.error(f"An unexpected error occurred while trying to kill process {processID}: {e}")
        print(f"An unexpected error occurred while trying to kill process {processID}: {e}") # Optional: Inform the user.
        raise # Re-raise the exception to signal the failure to the caller.


if __name__ == '__main__':
    # Example usage (replace with a valid process ID for testing)
    try:
        # Replace 12345 with a valid process ID for testing.  This is just an example.
        killProcess(12345)
    except ValueError as e:
        print(f"Error: {e}")
    except PermissionError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

