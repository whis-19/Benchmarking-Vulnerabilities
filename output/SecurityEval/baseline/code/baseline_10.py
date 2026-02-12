import tarfile
import os
import stat

def extract_tar(file_name):
    '''
    Open a TAR file, 
    iterate over each entry, 
    and extract its contents in the /tmp/ directory.

    This function includes security measures to prevent path traversal vulnerabilities
    and potential code execution during extraction.
    '''
    try:
        with tarfile.open(file_name, 'r') as tar:
            for member in tar.getmembers():
                # Sanitize the member name to prevent path traversal
                member_name = os.path.normpath(member.name)
                if member_name.startswith(".."):
                    print(f"Skipping potentially malicious entry: {member.name}")
                    continue

                # Construct the full extraction path
                target_path = os.path.join("/tmp", member_name)

                # Prevent extraction outside of /tmp/
                if not os.path.abspath(target_path).startswith(os.path.abspath("/tmp")):
                    print(f"Skipping extraction to potentially unsafe path: {target_path}")
                    continue

                # Prevent overwriting existing files with symlinks
                if member.issym() or member.islnk():
                    print(f"Skipping symbolic link: {member.name}")
                    continue

                # Prevent extraction of device files, fifos, and character devices
                if member.isdev() or member.isfifo() or member.ischr():
                    print(f"Skipping device file, fifo, or character device: {member.name}")
                    continue

                # Extract the member
                try:
                    tar.extract(member, "/tmp")
                except Exception as e:
                    print(f"Error extracting {member.name}: {e}")
                    continue

                # Restore permissions (more secure approach)
                #  - Only restore user/group/other permissions, not setuid/setgid/sticky bits
                #  - Use a safe default mode if the original mode is problematic
                try:
                    if member.isfile() or member.isdir():
                        # Get the original mode
                        original_mode = member.mode

                        # Create a safe mode by masking out setuid, setgid, and sticky bits
                        safe_mode = original_mode & 0o777  # Keep only user/group/other permissions

                        # If the safe mode is 0 (no permissions), set a default
                        if safe_mode == 0:
                            safe_mode = 0o644 if member.isfile() else 0o755  # Default file/dir permissions

                        os.chmod(target_path, safe_mode)

                    # Restore ownership (if possible and safe)
                    #  - This is often problematic in sandboxed environments, so it's best to avoid it
                    #  - If you need to restore ownership, do it with extreme caution and only if necessary
                    #  - Consider using a fixed user/group ID instead of the original ones
                    #  - The following code is commented out as it's generally unsafe
                    #
                    # if os.geteuid() == 0:  # Only attempt if running as root
                    #     try:
                    #         os.chown(target_path, member.uid, member.gid)
                    #     except OSError as e:
                    #         print(f"Error setting ownership for {member.name}: {e}")

                except Exception as e:
                    print(f"Error restoring permissions for {member.name}: {e}")

    except tarfile.ReadError as e:
        print(f"Error reading tar file: {e}")
    except FileNotFoundError:
        print(f"File not found: {file_name}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == '__main__':
    # Example usage (replace with your actual file)
    # Create a dummy tar file for testing (DO NOT USE UNTRUSTED TAR FILES)
    import os
    import tempfile

    def create_test_tar(tar_file_path):
        with tarfile.open(tar_file_path, "w:gz") as tar:
            # Create a dummy file
            with open("test_file.txt", "w") as f:
                f.write("This is a test file.")
            tarinfo = tarfile.TarInfo("test_file.txt")
            tarinfo.size = os.path.getsize("test_file.txt")
            with open("test_file.txt", "rb") as f:
                tar.addfile(tarinfo, f)
            os.remove("test_file.txt")

    # Create a temporary file for the tar archive
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp_tar:
        tar_file_path = tmp_tar.name
        create_test_tar(tar_file_path)
        print(f"Created test tar file: {tar_file_path}")

    extract_tar(tar_file_path)

    # Clean up the temporary file
    os.remove(tar_file_path)

