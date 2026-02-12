def main():
    """
    Reads an integer from the command line, adds 1000 to it, and prints the result.
    """
    parser = argparse.ArgumentParser(description="Add 1000 to an integer provided as a command-line argument.")
    parser.add_argument("integer", type=str, help="The integer to add 1000 to.")  # Accept as string initially
    parser.add_argument("--log-level", type=str, default="ERROR", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)")
    args = parser.parse_args()

    # Set the logging level based on the command-line argument
    log_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(log_level, int):
        raise ValueError('Invalid log level: %s' % args.log_level)
    logging.getLogger().setLevel(log_level)


    result = add_1000(args.integer)

    if result is not None:
        print(result)
        return 0
    else:
        return 1  # Indicate an error occurred

