import os
    import stat
    import time

    def format_file_info(filepath):
        """Formats file information similar to ls -l."""
        try:
            st = os.stat(filepath)
            # Permissions
            mode = st.st_mode
            permissions = ""
            permissions += "r" if mode & stat.S_IRUSR else "-"
            permissions += "w" if mode & stat.S_IWUSR else "-"
            permissions += "x" if mode & stat.S_IXUSR else "-"
            permissions += "r" if mode & stat.S_IRGRP else "-"
            permissions += "w" if mode & stat.S_IWGRP else "-"
            permissions += "x" if mode & stat.S_IXGRP else "-"
            permissions += "r" if mode & stat.S_IROTH else "-"
            permissions += "w" if mode & stat.S_IWOTH else "-"
            permissions += "x" if mode & stat.S_IXOTH else "-"

            # Number of hard links (simplified to 1 for this example)
            hard_links = 1

            # Owner and group (simplified to user ID and group ID)
            owner = st.st_uid
            group = st.st_gid

            # File size
            size = st.st_size

            # Last modification time
            modification_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))

            # Filename
            filename = os.path.basename(filepath)

            return f"{permissions} {hard_links} {owner} {group} {size} {modification_time} {filename}"
        except OSError as e:
            return f"Error getting file info for {filepath}: {e}"

    try:
        file_list = os.listdir(target_directory)
        formatted_file_list = []
        for filename in file_list:
            filepath = os.path.join(target_directory, filename)
            formatted_file_list.append(format_file_info(filepath))
        response_text = "\n".join(formatted_file_list)
        return Response(response_text, status=200)
    except FileNotFoundError:
        return Response("Directory not found", status=404)
    except OSError as e:
        print(f"Error listing files: {e}") # Log the error
        return Response(f"Error listing files", status=500) # Don't expose details to the client

