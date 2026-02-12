from file_utils import readFile, calculate_hash

    try:
        content = readFile("my_file.txt")
        file_hash = calculate_hash(content)
        print(f"File hash: {file_hash}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except ValueError as e:
        print(f"Error: {e}")

