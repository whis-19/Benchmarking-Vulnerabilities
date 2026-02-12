# Example usage (assuming you have a file named "my_file.txt" in /app/safe_files)
try:
    content = readFile("my_file.txt")
    if content:
        print("File content:", content)
except FileNotFoundError as e:
    print(f"Error: {e}")
except ValueError as e:
    print(f"Error: {e}")

# Example of an invalid filename
try:
    content = readFile("../../../etc/passwd")  # Attempt to access a file outside the safe folder
except FileNotFoundError as e:
    print(f"Error: {e}")
except ValueError as e:
    print(f"Error: {e}")

