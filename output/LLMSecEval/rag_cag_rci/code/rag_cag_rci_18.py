import resource

    def execute_command_in_sandbox(command, args, chroot_dir):
        # ...

        def preexec_fn():
            # Set resource limits before executing the command
            resource.setrlimit(resource.RLIMIT_CPU, (1, 1))  # 1 second CPU time limit
            resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 100, 1024 * 1024 * 100))  # 100MB address space limit

        process = subprocess.Popen(full_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=preexec_fn)
        # ...

