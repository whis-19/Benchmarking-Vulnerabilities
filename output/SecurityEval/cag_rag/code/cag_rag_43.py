import os
import signal

def killProcess(processID):
    '''
    Kill the process with the given processID.
    '''
    try:
        pid = int(processID)  # Ensure processID is an integer
        os.kill(pid, signal.SIGTERM)  # Send SIGTERM signal
        print(f"Process with PID {pid} terminated.")
    except ValueError:
        print("Invalid process ID. Must be an integer.")
    except ProcessLookupError:
        print(f"Process with PID {processID} not found.")
    except PermissionError:
        print(f"Insufficient permissions to kill process with PID {processID}.")
    except Exception as e:
        print(f"An error occurred: {e}")

