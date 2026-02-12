if __name__ == "__main__":
        try:
            filename = get_argument_at_index(1)
            if filename:
                execute_command_safely(filename)
        except (IndexError, ValueError) as e:
            print(f"Error: {e}")
            sys.exit(1) # Exit with an error code

