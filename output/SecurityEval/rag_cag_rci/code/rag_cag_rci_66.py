content, error = readFile("my_file.txt")  # Example: Read my_file.txt

if error:
    print(f"Error reading file: {error}")
else:
    print(f"File content: {content}")

content, error = readFile("../../../etc/passwd") # Example: Attempted path traversal

if error:
    print(f"Error reading file: {error}") # This will print an error message
else:
    print(f"File content: {content}")

