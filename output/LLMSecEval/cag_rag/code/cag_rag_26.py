file_content = read_safe_file("my_document.txt")

if file_content:
    print("File content:")
    print(file_content)
else:
    print("Failed to read the file.")

file_content = read_safe_file("../../../etc/passwd") # This will be blocked
file_content = read_safe_file("my_document.exe") # This will be blocked
file_content = read_safe_file("my/document.txt") # This will be blocked

