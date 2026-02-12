import os
import signal
import logging
import psutil  # Requires installing psutil: pip install psutil
import getpass

# Configure logging (optional, but highly recommended)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def killProcess(processID, allowed_pids=None, must_be_owned_by_user=None):
    '''
    Kill the process with the given processID, with enhanced validation.

    Args:
        processID (int): The process ID to kill.
        allowed_pids (list, optional): A list of allowed PIDs. If provided, processID must be in this list.
        must_be_owned_by_user (str, optional): The username that must own the process.

    Raises:
        TypeError: If processID is not an integer.
        ValueError: If processID is not a positive integer or if validation fails.
        OSError: If the process does not exist or if the user does not have permission to kill it.
    '''
    if not isinstance(processID, int):
        raise TypeError("processID must be an integer.")

    if processID <= 0:
        raise ValueError("processID must be a positive integer.")

    # Defense in Depth:  Further check on processID range (optional)
    if processID > 65535:  # Maximum PID value (implementation-dependent)
        logging.warning(f"Process ID {processID} exceeds maximum possible value.  Possible integer overflow attempt?")
        raise ValueError("processID is suspiciously large.")

    # Enhanced Validation
    if allowed_pids is not None and processID not in allowed_pids:
        logging.warning(f"Process ID {processID} is not in the allowed list: {allowed_pids}")
        raise ValueError("Process ID is not allowed.")

    if must_be_owned_by_user is not None:
        try:
            process = psutil.Process(processID)
            process_username = process.username()  # Requires root privileges to get username of other users
            if process_username != must_be_owned_by_user:
                logging.warning(f"Process {processID} is not owned by user {must_be_owned_by_user}, but by {process_username}")
                raise ValueError(f"Process is not owned by the required user: {must_be_owned_by_user}")
        except psutil.NoSuchProcess:
            logging.warning(f"Process {processID} not found during validation.")
            raise OSError(os.errno.ESRCH, "No such process")
        except psutil.AccessDenied:
            logging.warning(f"Access denied when trying to get information about process {processID}.")
            raise OSError(os.errno.EPERM, "Permission denied")
        except Exception as e:
            logging.error(f"Error during process validation: {e}")
            raise  # Re-raise the exception

    try:
        os.kill(processID, signal.SIGTERM)  # Send SIGTERM first (graceful termination)
        logging.info(f"Sent SIGTERM to process {processID}")

        # Potential Race Condition Handling (Retry Mechanism - Optional)
        import time
        for i in range(3):  # Retry up to 3 times
            time.sleep(0.1)
            try:
                os.kill(processID, 0)  # Check if process still exists
                logging.warning(f"Process {processID} still exists after sending SIGTERM.  Retry {i+1}/3.")
            except OSError as e:
                if e.errno == os.errno.ESRCH:
                    logging.info(f"Process {processID} terminated gracefully after SIGTERM.")
                    return  # Process terminated successfully
                else:
                    logging.error(f"Unexpected error checking process {processID}: {e}")
                    raise  # Re-raise the exception
        logging.warning(f"Process {processID} did not terminate gracefully after multiple retries.")


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


def forceKillProcess(processID, allowed_pids=None, must_be_owned_by_user=None):
    '''
    Forcefully kill the process with the given processID using SIGKILL.
    Use this only if SIGTERM fails.

    Args:
        processID (int): The process ID to kill.
        allowed_pids (list, optional): A list of allowed PIDs. If provided, processID must be in this list.
        must_be_owned_by_user (str, optional): The username that must own the process.

    Raises:
        TypeError: If processID is not an integer.
        ValueError: If processID is not a positive integer or if validation fails.
        OSError: If the process does not exist or if the user does not have permission to kill it.
    '''
    if not isinstance(processID, int):
        raise TypeError("processID must be an integer.")

    if processID <= 0:
        raise ValueError("processID must be a positive integer.")

    # Defense in Depth:  Further check on processID range (optional)
    if processID > 65535:  # Maximum PID value (implementation-dependent)
        logging.warning(f"Process ID {processID} exceeds maximum possible value.  Possible integer overflow attempt?")
        raise ValueError("processID is suspiciously large.")

    # Enhanced Validation
    if allowed_pids is not None and processID not in allowed_pids:
        logging.warning(f"Process ID {processID} is not in the allowed list: {allowed_pids}")
        raise ValueError("Process ID is not allowed.")

    if must_be_owned_by_user is not None:
        try:
            process = psutil.Process(processID)
            process_username = process.username()  # Requires root privileges to get username of other users
            if process_username != must_be_owned_by_user:
                logging.warning(f"Process {processID} is not owned by user {must_be_owned_by_user}, but by {process_username}")
                raise ValueError(f"Process is not owned by the required user: {must_be_owned_by_user}")
        except psutil.NoSuchProcess:
            logging.warning(f"Process {processID} not found during validation.")
            raise OSError(os.errno.ESRCH, "No such process")
        except psutil.AccessDenied:
            logging.warning(f"Access denied when trying to get information about process {processID}.")
            raise OSError(os.errno.EPERM, "Permission denied")
        except Exception as e:
            logging.error(f"Error during process validation: {e}")
            raise  # Re-raise the exception

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

        # Example:  Only allow killing the current process
        allowed_pids = [current_pid]

        # Example:  Only allow killing processes owned by the current user
        current_user = getpass.getuser()  # Or use getpass.getuser()
        print(f"Current user: {current_user}")

        # Attempt graceful termination first
        killProcess(current_pid, allowed_pids=allowed_pids, must_be_owned_by_user=current_user)

        # Optionally, wait a short time to see if the process terminates gracefully
        import time
        time.sleep(1)

        # If the process is still running, use forceKillProcess (use with caution!)
        # forceKillProcess(current_pid, allowed_pids=allowed_pids, must_be_owned_by_user=current_user)

    except TypeError as e:
        print(f"TypeError: {e}")
    except ValueError as e:
        print(f"ValueError: {e}")
    except OSError as e:
        print(f"OSError: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

