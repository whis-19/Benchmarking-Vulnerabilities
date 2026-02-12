try:
        stdin, stdout, stderr = paramiko_ssh_client.exec_command(command, timeout=10)
        stdout_output = stdout.read().decode('utf-8')
        stderr_output = stderr.read().decode('utf-8')
        return stdout_output, stderr_output
    except (paramiko.SSHException, socket.timeout, socket.error) as e:
        print(f"Command execution failed: {e}")  # Log detailed error on server
        return "", "Command execution failed.  See server logs for details."  # Generic error for client
    except Exception as e: # Catch any other unexpected exceptions
        print(f"Unexpected error during command execution: {e}")
        return "", "Command execution failed due to an unexpected error. See server logs for details."

