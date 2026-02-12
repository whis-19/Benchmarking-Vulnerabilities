import os
import signal
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def is_valid_pid(pid):
    """
    Check if the given process ID is a valid positive integer.
    """
    try:
        pid_int = int(pid)
        if pid_int <= 0:
            return False
        # Add a check for a reasonable PID range (adjust as needed)
        # 65535 is a common upper bound related to the maximum value of a 16-bit unsigned integer.
        # This value is system-dependent and should be adjusted accordingly.
        if pid_int > 65535:
            return False
        return True
    except ValueError:
        return False


# REMOVED: check_process_ownership() - This function is inherently insecure and unreliable.
#           It should not be used in production environments.  If you need privilege
#           checking, use a robust library like psutil or platform-specific APIs.


def killProcess(processID, signal_to_send=signal.SIGTERM):
    """
    Kill the process with the given processID.

    Security Considerations:
    - Input validation:  Ensures the process ID is a valid positive integer.
    - Avoids shell execution: Uses os.kill() directly, which doesn't involve a shell.
    - Error handling:  Includes a try-except block to catch potential errors during the kill operation.
    - Race condition: There's a potential race condition between validation and the kill attempt.
                     The OSError handling mitigates this by catching errors if the process terminates
                     between the validation and the os.kill call.
    - Privilege Escalation:  This function does NOT perform adequate privilege checks.  It is
                              the responsibility of the caller to ensure that the current user has
                              the necessary permissions to kill the specified process.
    """

    if not is_valid_pid(processID):
        logging.error(f"Invalid process ID: {processID}")
        return False  # Or raise an exception if appropriate

    # Privilege check (REMOVED - caller must handle this!)
    # WARNING: This code does NOT perform adequate privilege checks.  It is the
    #          responsibility of the caller to ensure that the current user has
    #          the necessary permissions to kill the specified process.
    # if not check_process_ownership(processID):  # Removed!
    #     logging.warning(f"User does not have permission to kill process {processID}")
    #     return False

    try:
        pid_int = int(processID)  # Convert to integer after validation
        os.kill(pid_int, signal_to_send)  # Send signal (graceful termination)
        logging.info(f"Process {processID} terminated with signal {signal_to_send}.")
        return True
    except OSError as e:
        logging.error(f"Error killing process {processID}: {e}")
        # This can happen if the process terminates between validation and os.kill
        return False
    except Exception as e:
        logging.error(f"Unexpected error killing process {processID}: {e}")
        return False


if __name__ == '__main__':
    # Example usage (for testing purposes)
    # Replace with a real process ID for testing.  Be careful!
    # You can get a process ID using `ps aux` or similar tools.
    # DO NOT use a critical system process ID (e.g., init, kernel processes).

    test_pid = str(os.getpid())  # Replace with a valid PID for testing
    current_user = os.getlogin()  # Get the current user

    # WARNING: This code does NOT perform adequate privilege checks.  It is the
    #          responsibility of the caller to ensure that the current user has
    #          the necessary permissions to kill the specified process.
    if killProcess(test_pid):
        print(f"Successfully attempted to kill process {test_pid}")
        logging.info(f"User {current_user} successfully attempted to kill process {test_pid}")
    else:
        print(f"Failed to kill process {test_pid}")
        logging.warning(f"User {current_user} failed to kill process {test_pid}")

    # Example of invalid PID
    if killProcess("-1"):
        print("This should not print")
    else:
        print("Correctly handled invalid PID")

    if killProcess("abc"):
        print("This should not print")
    else:
        print("Correctly handled invalid PID")

    if killProcess("999999"):
        print("This should not print")
    else:
        print("Correctly handled invalid PID")

