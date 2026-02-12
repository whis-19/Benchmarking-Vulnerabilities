import os
import signal

def killProcess(processID):
    """
    Kill the process with the given processID.

    This function uses the `os.kill` function to send a SIGTERM signal to the process.
    It avoids shell execution and does not rely on external commands.

    Args:
        processID: The ID of the process to kill.  Must be an integer.

    Raises:
        TypeError: If processID is not an integer.
        ValueError: If processID is not a positive integer.
        ProcessLookupError: If the process with the given ID does not exist.
        OSError: If there is a permission error or other OS-related error.
    """

    if not isinstance(processID, int):
        raise TypeError("processID must be an integer")

    if processID <= 0:
        raise ValueError("processID must be a positive integer")

    try:
        os.kill(processID, signal.SIGTERM)  # Send SIGTERM signal
    except ProcessLookupError:
        raise ProcessLookupError(f"Process with ID {processID} not found")
    except OSError as e:
        # Handle permission errors or other OS-related errors
        raise OSError(f"Error killing process {processID}: {e}")


if __name__ == '__main__':
    # Example usage (demonstration only - be careful when killing processes!)
    # This example requires you to know a valid process ID.  Replace 12345 with a real PID.
    # You can find a PID using tools like `ps` or `top`.
    try:
        # Replace 12345 with a valid process ID for testing.  DO NOT use a critical system process ID.
        # This is just an example and should be used with extreme caution.
        # It's best to create a dummy process for testing purposes.
        # For example, you could start a simple Python script in the background and get its PID.
        # Then, use that PID here.
        killProcess(12345)  # Replace with a valid PID for testing
        print("Process killed (if it existed and we had permission).")
    except (TypeError, ValueError, ProcessLookupError, OSError) as e:
        print(f"Error: {e}")

