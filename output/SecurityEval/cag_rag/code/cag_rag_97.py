try:
    root = get_root()
    # Process the XML root element
    print(root.tag)
except ValueError as e:
    print(f"Error: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")

