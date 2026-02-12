import sys
import signal
import argparse
import threading
import resource  # Optional
import os  # For checking root privileges

class InputError(Exception):
    pass

def inputInt(prompt="Enter an integer: ", min_val=None, max_val=None, allowed_values=None, business_rules=None, business_rules_timeout=None, max_attempts=3, use_threading_timer=False, use_resource_limits=False):
    """
    Take an int input and return it after checking type and applying security measures.

    Args:
        prompt (str, optional): The prompt to display to the user. Defaults to "Enter an integer: ".
        min_val (int, optional): The minimum acceptable value. Defaults to None.
        max_val (int, optional): The maximum acceptable value. Defaults to None.
        allowed_values (list, optional): A list of allowed integer values. Defaults to None.
        business_rules (callable, optional): A function that takes the integer as input and returns True if it satisfies the business rules, False otherwise.  SHOULD NOT HAVE SIDE EFFECTS. Defaults to None.
        business_rules_timeout (int, optional): Timeout in seconds for the business_rules function.  Defaults to None.
        max_attempts (int, optional): Maximum number of attempts allowed. Defaults to 3.
        use_threading_timer (bool, optional): Use threading.Timer for business rules timeout (more robust but requires restructuring). Defaults to False.
        use_resource_limits (bool, optional): Use resource module to limit CPU time. Requires root privileges to raise limits. Defaults to False.

    Returns:
        int: The validated integer input.

    Raises:
        InputError: If the input is not an integer, or if it violates any of the specified constraints (min_val, max_val, allowed_values, business_rules), or if the maximum number of attempts is exceeded.
    """

    attempts = 0
    while True:
        attempts += 1
        if attempts > max_attempts:
            raise InputError("Too many invalid attempts.")

        try:
            user_input = input(prompt)

            # Input Validation: Check if the input is a valid integer
            try:
                num = int(user_input)
            except ValueError:
                print("Invalid input. Please enter a valid integer.")
                continue

            # Input Validation: Check if the input is within the allowed range
            if min_val is not None and num < min_val:
                print(f"Input is too small. Please enter a value greater than or equal to {min_val}.")
                continue

            if max_val is not None and num > max_val:
                print(f"Input is too large. Please enter a value less than or equal to {max_val}.")
                continue

            # Input Validation: Check if the input is in the allowed values list
            if allowed_values is not None and num not in allowed_values:
                print(f"Invalid input. Please enter one of the following values: {allowed_values}")
                continue

            # Input Validation: Check if the input satisfies the business rules
            if business_rules is not None:
                if use_threading_timer:
                    try:
                        result = [None]  # Use a list to store the result from the timer thread
                        def run_business_rules():
                            try:
                                result[0] = business_rules(num)
                            except Exception as e:
                                result[0] = e  # Store the exception

                        timer = threading.Timer(business_rules_timeout, lambda: result.__setitem__(0, False)) # Set result to False on timeout
                        timer.start()
                        business_rules_thread = threading.Thread(target=run_business_rules)
                        business_rules_thread.start()
                        business_rules_thread.join(business_rules_timeout) # Wait for the thread to finish or timeout

                        timer.cancel() # Cancel the timer if the thread finishes before the timeout

                        if result[0] is None:
                            print("Business rules check timed out.  Possible malicious function.")
                            continue
                        elif isinstance(result[0], Exception):
                            print(f"Error during business rules execution: {result[0]}")
                            continue
                        elif not result[0]:
                            print("Input does not satisfy the business rules.")
                            continue

                    except Exception as e:
                        print(f"Error during business rules execution: {e}")
                        continue

                else:  # Use signal.alarm
                    try:
                        if business_rules_timeout:
                            signal.alarm(business_rules_timeout)  # Set the alarm

                        if use_resource_limits:
                            try:
                                # Set resource limits (example: CPU time limit)
                                if os.geteuid() == 0: # Check if running as root
                                    resource.setrlimit(resource.RLIMIT_CPU, (business_rules_timeout + 1, business_rules_timeout + 1))  # Soft and hard limits
                                else:
                                    print("Warning: Resource limits requested but not running as root.  Limits will not be applied.")

                                if not business_rules(num):
                                    print("Input does not satisfy the business rules.")
                                    continue

                            except TimeoutError:
                                print("Business rules check timed out.  Possible malicious function.")
                                continue
                            except OSError as e:
                                print(f"Resource limit error: {e}") # Handle resource limit errors
                                continue
                            finally:
                                if os.geteuid() == 0:
                                    resource.setrlimit(resource.RLIMIT_CPU, (-1, -1)) # Reset to unlimited
                                signal.alarm(0)  # Disable the alarm
                        else:
                            if not business_rules(num):
                                print("Input does not satisfy the business rules.")
                                continue

                    except TimeoutError:
                        print("Business rules check timed out.  Possible malicious function.")
                        continue  # Or raise an exception, depending on your needs
                    finally:
                        signal.alarm(0)  # Disable the alarm

            return num

        except EOFError:
            print("\nEOFError: Input interrupted.")
            raise InputError("EOFError: Input interrupted.")

        except KeyboardInterrupt:
            print("\nKeyboardInterrupt: Input interrupted.")
            raise InputError("KeyboardInterrupt: Input interrupted.")


def main():
    parser = argparse.ArgumentParser(description="Get an integer from the command line or interactively.")
    parser.add_argument("integer", type=int, nargs='?', help="An integer value")
    args = parser.parse_args()

    if args.integer is not None:
        # Integer Overflow Check
        if args.integer > sys.maxsize or args.integer < -(sys.maxsize + 1):
            print("Error: Integer is too large or too small.")
        else:
            print(f"Integer from command line: {args.integer}")
    else:
        try:
            age = inputInt("Enter your age: ", use_threading_timer=False, use_resource_limits=False) # Example:  Resource limits disabled by default
            print(f"Your age is: {age}")
        except InputError as e:
            print(f"Error: {e}")


if __name__ == '__main__':
    main()

