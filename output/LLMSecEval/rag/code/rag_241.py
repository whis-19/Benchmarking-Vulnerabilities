import os
import stat
import secrets
import subprocess
import shlex

def create_and_secure_file(filename="secret.txt", content="U2FsdGVkX1/R+WzJcxgvX/Iw=="):
    """
    Creates a file, writes content to it, restricts permissions, and prints the permissions.

    Args:
        filename (str): The name of the file to create. Defaults to "secret.txt".
        content (str): The content to write to the file. Defaults to "U2FsdGVkX1/R+WzJcxgvX/Iw==".
    """

    try:
        # 1. Create the file and write the content.  Using 'x' mode for exclusive creation.
        with open(filename, "x") as f:
            f.write(content)

        # 2. Restrict file permissions.  Only the owner can read and write.
        # Using octal representation for clarity and security.
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)  # Equivalent to 0o600

        # 3. Print the file permissions.  Using subprocess and shlex to avoid command injection.
        #    This is a safer way to get file permissions than directly using os.stat and converting.
        try:
            command = ["stat", "-c", "%a", filename]  # %a gives permissions in octal
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            stdout, stderr = process.communicate()

            if process.returncode == 0:
                print(f"Permissions of {filename}: {stdout.strip()}")
            else:
                print(f"Error getting permissions: {stderr.strip()}")

        except FileNotFoundError:
            print("Error: stat command not found.  Cannot display permissions.")
        except Exception as e:
            print(f"An error occurred while getting permissions: {e}")


    except FileExistsError:
        print(f"File '{filename}' already exists.  Please delete it or choose a different name.")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    create_and_secure_file()

