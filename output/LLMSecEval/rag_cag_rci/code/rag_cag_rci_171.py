try:
        result = subprocess.run(command_list, capture_output=True, text=True, check=False, timeout=10)
        if result.returncode != 0:
            logging.error(f"Command '{command}' failed with return code {result.returncode}. Stderr: {result.stderr}")
            print(f"Error: Command '{command}' failed with return code {result.returncode}")
            return None, None, None
        return result.returncode, result.stdout, result.stderr
    except ...:
        ...

