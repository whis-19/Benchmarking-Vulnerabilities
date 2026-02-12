import os
import fcntl
import stat
import logging
import json
import subprocess
import shlex
import tempfile
import shutil
import pwd
import grp
import bcrypt  # For password hashing

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_and_write_config(config_file_path, sensitive_data):
    """
    Creates a configuration file, writes sensitive data to it, and sets secure permissions.

    Args:
        config_file_path (str): The path to the configuration file.
        sensitive_data (dict): A dictionary containing the sensitive data to be written to the file.
    """

    try:
        # 1. Protect access to configuration files: Use a temporary file for writing, then rename.
        temp_config_file = tempfile.NamedTemporaryFile(delete=False, mode='w')
        temp_config_path = temp_config_file.name

        try:
            # 2.  Do not store username and passwords in configurations files in cleartext: Hash passwords.
            #    (Example:  Use a proper password hashing library like bcrypt or argon2)
            #    For demonstration, we'll just store a placeholder.  NEVER store real passwords like this.
            hashed_data = {}
            for key, value in sensitive_data.items():
                if key.lower().endswith("password"):
                    # Replace with actual password hashing (bcrypt, argon2)
                    password = value.encode('utf-8')  # Encode to bytes
                    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
                    # IMPORTANT: bcrypt is suitable for password hashing.
                    # The goal here is to show the *process* of hashing, not to provide a secure solution.
                    hashed_data[key] = hashed_password
                else:
                    hashed_data[key] = value

            # Write the data to the temporary file as JSON.
            json.dump(hashed_data, temp_config_file, indent=4)
            temp_config_file.flush()  # Ensure data is written to disk
        except Exception as e:
            logging.error(f"Error writing to temporary config file: {e}")
            raise
        finally:
            temp_config_file.close()

        # 3. Restrict permissions to files that cannot be encrypted: Set permissions before renaming.
        # Set permissions: owner read/write, group read, others none.
        os.chmod(temp_config_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)

        # 4. Atomic rename to prevent race conditions.
        os.rename(temp_config_path, config_file_path)
        logging.info(f"Configuration file created/updated successfully at: {config_file_path}")

    except Exception as e:
        logging.error(f"Error creating/updating configuration file: {e}")
        # Clean up the temporary file if an error occurred.
        try:
            os.remove(temp_config_path)
        except OSError:
            pass  # Ignore errors during cleanup
        raise

def execute_command_with_sandbox(command, user=None, group=None):
    """
    Executes a command in a sandboxed environment using chroot.

    Args:
        command (str): The command to execute.
        user (str, optional): The username to run the command as. Defaults to None.
        group (str, optional): The group name to run the command as. Defaults to None.
    """
    try:
        # 1. Use vetted library or framework that prevents OS command injection weakness: shlex.split
        command_list = shlex.split(command)

        # 2. Keep the data used to generate an executable command out of external control:  Command is hardcoded.
        #    If you *must* use external data, validate and sanitize it rigorously.
        # Even with shlex.split(), if any part of the *arguments* to the command comes from external input,
        # it *must* be validated and sanitized. shlex.split() prevents injection via the command itself,
        # but not necessarily via its arguments.

        # 3. Execute external commands that only created statically: Command is defined in code.

        # Create a temporary directory for the chroot environment.
        with tempfile.TemporaryDirectory() as chroot_dir:
            # Create necessary directories inside the chroot.  This is a *very* basic example.
            # In a real application, you'd need to copy necessary binaries, libraries, and data.
            os.makedirs(os.path.join(chroot_dir, "bin"), exist_ok=True)
            os.makedirs(os.path.join(chroot_dir, "tmp"), exist_ok=True)  # Example: /tmp
            os.makedirs(os.path.join(chroot_dir, "dev"), exist_ok=True) # Add /dev

            # Copy essential binaries (e.g., /bin/sh) into the chroot.  This is a simplified example.
            # In a real chroot, you'd need to copy *all* dependencies.
            try:
                shutil.copy2("/bin/sh", os.path.join(chroot_dir, "bin"))
                # Example of finding dependencies (requires ldd to be present)
                # dependencies = subprocess.check_output(["ldd", "/bin/sh"]).decode().splitlines()
                # For each dependency, copy it into the chroot.  This is a simplified example.
                # Also, note that ldd itself might have dependencies.
            except FileNotFoundError:
                logging.warning("Warning: /bin/sh not found.  Chroot may not function correctly.")
            except IOError as e:
                logging.error(f"Error copying /bin/sh: {e}")
                raise

            # Create minimal /dev/null and /dev/urandom inside chroot
            dev_null_path = os.path.join(chroot_dir, "dev", "null")
            dev_urandom_path = os.path.join(chroot_dir, "dev", "urandom")
            try:
                os.mknod(dev_null_path, stat.S_IFCHR | 0o666, os.makedev(1, 3))
                os.mknod(dev_urandom_path, stat.S_IFCHR | 0o666, os.makedev(1, 9))
            except OSError as e:
                logging.error(f"Error creating /dev/null or /dev/urandom: {e}")
                raise

            # Set up user and group inside the chroot (if specified).
            uid = None
            gid = None
            if user:
                try:
                    # Check if the user exists *before* getting the UID.
                    try:
                        user_info = pwd.getpwnam(user)
                    except KeyError:
                        # User doesn't exist on the host, try creating it inside the chroot
                        logging.warning(f"User {user} not found on host, attempting to create inside chroot.")
                        # This is a simplified example, creating users properly inside a chroot is complex
                        # and requires creating /etc/passwd and /etc/group inside the chroot.
                        # For demonstration purposes, we'll just raise an error.
                        raise Exception(f"User {user} not found.  Creating users inside chroot not fully implemented.")

                    uid = user_info.pw_uid
                except KeyError:
                    logging.error(f"User {user} not found.")
                    raise
            if group:
                try:
                    # Check if the group exists *before* getting the GID.
                    try:
                        group_info = grp.getgrnam(group)
                    except KeyError:
                        # Group doesn't exist on the host, try creating it inside the chroot
                        logging.warning(f"Group {group} not found on host, attempting to create inside chroot.")
                        # This is a simplified example, creating groups properly inside a chroot is complex
                        # and requires creating /etc/passwd and /etc/group inside the chroot.
                        # For demonstration purposes, we'll just raise an error.
                        raise Exception(f"Group {group} not found. Creating groups inside chroot not fully implemented.")
                    gid = group_info.gr_gid
                except KeyError:
                    logging.error(f"Group {group} not found.")
                    raise

            # Create a subprocess and chroot into the temporary directory.
            process = subprocess.Popen(
                command_list,
                cwd="/",  # Important: Set cwd to / *after* chrooting.
                preexec_fn=lambda: os.chroot(chroot_dir),
                user=uid,
                group=gid,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                executable="/bin/sh" if os.path.exists("/bin/sh") else None # Specify executable if needed
            )

            stdout, stderr = process.communicate()

            if process.returncode != 0:
                logging.error(f"Command failed with return code {process.returncode}")
                logging.error(f"Stdout: {stdout.decode()}")
                logging.error(f"Stderr: {stderr.decode()}")
                raise Exception(f"Command execution failed: {stderr.decode()}")
            else:
                logging.info(f"Command executed successfully.")
                logging.info(f"Stdout: {stdout.decode()}")

    except Exception as e:
        logging.error(f"Error executing command in sandbox: {e}")
        raise

if __name__ == "__main__":
    config_file = "important_config.json"
    sensitive_data = {
        "database_url": "example.com",
        "api_key": "some_api_key",
        "admin_password": "admin_password"  # This is just an example.  NEVER store passwords like this.
    }

    try:
        create_and_write_config(config_file, sensitive_data)

        # Example of executing a command in a sandbox.
        # This is a *very* basic example.  A real chroot environment requires much more setup.
        command_to_execute = "ls /tmp"  # List the contents of /tmp inside the chroot.
        execute_command_with_sandbox(command_to_execute, user="nobody", group="nogroup") # Run as a less privileged user.

    except Exception as e:
        logging.error(f"An error occurred: {e}")

