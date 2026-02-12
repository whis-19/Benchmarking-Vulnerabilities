try:
        if secure_file_creation("my_file.txt", "Some content", truncate_if_exists=False):
            print("File created or opened successfully.")
        else:
            print("File creation failed (already exists).")
    except Exception as e:
        print(f"An error occurred: {e}")

