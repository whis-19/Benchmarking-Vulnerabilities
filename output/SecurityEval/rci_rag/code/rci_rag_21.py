if os.name != 'nt':
        try:
            subprocess.run(["ulimit", "-t", "5", "-m", "100000", "-v", "100000"], check=True)
            result = subprocess.run(
                ["python", temp_file_name],
                capture_output=True,
                text=True,
                timeout=5
            )
        except subprocess.CalledProcessError as e:
            logging.error(f"Error setting resource limits: {e}")
            return 1, "", f"Error setting resource limits: {e}"
    else:
        result = subprocess.run(
            ["python", temp_file_name],
            capture_output=True,
            text=True,
            timeout=5
        )

