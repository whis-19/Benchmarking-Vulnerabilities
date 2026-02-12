import os
import subprocess
import pwd
import grp
import logging
import shlex  # For safe command construction
import re  # For regular expression validation

def install_package_secure_with_priv_drop(package_name, install_user="nobody", venv_path=None):
    """
    Installs a package using pip in a secure manner, dropping privileges before execution.
    Uses a virtual environment for isolation.
    """
    try:
        # 1. Validate Package Name (More Robust Example)
        if not re.match(r"^[a-zA-Z0-9_-]+$", package_name):
            raise ValueError("Invalid package name: only alphanumeric characters, hyphens, and underscores allowed")

        # 2. Get User Information
        try:
            user_info = pwd.getpwnam(install_user)
            uid = user_info.pw_uid
            gid = user_info.pw_gid
        except KeyError:
            logging.error(f"User '{install_user}' not found.  Cannot drop privileges.")
            raise

        # 3. Create Virtual Environment (if specified)
        if venv_path:
            venv_command = ["python3", "-m", "venv", venv_path]  # Or "python" depending on your system
            subprocess.run(venv_command, check=True, capture_output=True, text=True) # Run as current user

            # Ensure the virtual environment is owned by the target user
            chown_command = ["chown", "-R", f"{install_user}:{install_user}", venv_path]
            subprocess.run(chown_command, check=True, capture_output=True, text=True, user=0) # Run as root

            pip_path = os.path.join(venv_path, "bin", "pip")
        else:
            pip_path = "pip"  # System pip - less secure

        # 4. Construct pip command safely
        command = [pip_path, "install", shlex.quote(package_name)]  # Use shlex.quote!

        def pre_exec():
            # Drop privileges
            os.setgid(gid)
            os.setuid(uid)

        # 5. Use subprocess.Popen with preexec_fn
        process = subprocess.Popen(command,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   text=True,
                                   preexec_fn=pre_exec)

        stdout, stderr = process.communicate()
        return_code = process.returncode

        logging.info(f"pip install output: {stdout}")
        logging.info(f"pip install errors: {stderr}")

        if return_code != 0:
            logging.error(f"Error installing package: {stderr}")
            raise subprocess.CalledProcessError(return_code, command, output=stdout, stderr=stderr)

        return stdout

    except subprocess.CalledProcessError as e:
        logging.error(f"Error installing package: {e}")
        raise
    except Exception as e:
        logging.exception(f"Unexpected error installing {package_name}")
        raise

# Example Usage (with virtual environment):
# install_package_secure_with_priv_drop("requests", install_user="nobody", venv_path="/opt/my_venv")

