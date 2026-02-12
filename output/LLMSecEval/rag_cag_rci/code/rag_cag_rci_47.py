import resource

    def execute_allowed_command(command, arguments):
        # ... (previous code) ...

        try:
            # Set resource limits (example)
            resource.setrlimit(resource.RLIMIT_CPU, (10, 10))  # 10 seconds CPU time
            resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 100, 1024 * 1024 * 100))  # 100MB memory

            result = subprocess.run([command] + arguments, capture_output=True, text=True, check=True)

            # ... (rest of the code) ...

        except resource.error as e:
            print(f"Error setting resource limits: {e}")
            return

