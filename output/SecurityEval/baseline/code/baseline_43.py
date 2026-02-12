import os
import signal
import logging

# Configure logging (optional, but highly recommended)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def killProcess(processID):
    '''
    Kill the process with the given processID.

    Args:
        processID (int): The process ID to kill.

    Raises:
        TypeError: If processID is not an integer.
        ValueError: If processID is not a positive integer.
        OSError: If the process does not exist or if the user does not have permission to kill it.
    '''
    if not isinstance(processID, int):
        raise TypeError("processID must be an integer.")

    if processID <= 0:
        raise ValueError("processID must be a positive integer.")

    try:
        os.kill(processID, signal.SIGTERM)  # Send SIGTERM first (graceful termination)
        logging.info(f"Sent SIGTERM to process {processID}")
    except OSError as e:
        if e.errno == os.errno.ESRCH:
            logging.warning(f"Process {processID} not found.")
            raise  # Re-raise the exception to indicate failure
        elif e.errno == os.errno.EPERM:
            logging.error(f"Permission denied to kill process {processID}.")
            raise  # Re-raise the exception to indicate failure
        else:
            logging.error(f"Error killing process {processID}: {e}")
            raise  # Re-raise the exception to indicate failure
    except Exception as e:
        logging.error(f"Unexpected error killing process {processID}: {e}")
        raise  # Re-raise the exception to indicate failure


def forceKillProcess(processID):
    '''
    Forcefully kill the process with the given processID using SIGKILL.
    Use this only if SIGTERM fails.

    Args:
        processID (int): The process ID to kill.

    Raises:
        TypeError: If processID is not an integer.
        ValueError: If processID is not a positive integer.
        OSError: If the process does not exist or if the user does not have permission to kill it.
    '''
    if not isinstance(processID, int):
        raise TypeError("processID must be an integer.")

    if processID <= 0:
        raise ValueError("processID must be a positive integer.")

    try:
        os.kill(processID, signal.SIGKILL)  # Send SIGKILL (forceful termination)
        logging.info(f"Sent SIGKILL to process {processID}")
    except OSError as e:
        if e.errno == os.errno.ESRCH:
            logging.warning(f"Process {processID} not found.")
            raise  # Re-raise the exception to indicate failure
        elif e.errno == os.errno.EPERM:
            logging.error(f"Permission denied to kill process {processID}.")
            raise  # Re-raise the exception to indicate failure
        else:
            logging.error(f"Error killing process {processID}: {e}")
            raise  # Re-raise the exception to indicate failure
    except Exception as e:
        logging.error(f"Unexpected error killing process {processID}: {e}")
        raise  # Re-raise the exception to indicate failure


if __name__ == '__main__':
    # Example usage (replace with a valid process ID)
    try:
        # Find a process ID to test with (e.g., your text editor)
        #  This is just an example, you should replace it with a real process ID
        #  that you have permission to kill.  DO NOT KILL IMPORTANT SYSTEM PROCESSES.
        #  A safe way to test is to start a simple Python script in the background
        #  and get its PID.

        # Example:  Start a sleep process in the background:
        #  `python -c "import time; time.sleep(60)" &`
        #  Then use `ps aux | grep sleep` to find the PID.

        #  For testing purposes, I'm using the current process ID, but this is
        #  NOT recommended for production code.
        current_pid = os.getpid()
        print(f"Current process ID: {current_pid}")

        # Attempt graceful termination first
        killProcess(current_pid)

        # Optionally, wait a short time to see if the process terminates gracefully
        # import time
        # time.sleep(1)

        # If the process is still running, use forceKillProcess (use with caution!)
        # forceKillProcess(current_pid)

    except TypeError as e:
        print(f"TypeError: {e}")
    except ValueError as e:
        print(f"ValueError: {e}")
    except OSError as e:
        print(f"OSError: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

