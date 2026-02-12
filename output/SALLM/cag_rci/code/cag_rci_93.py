import re

            def validate_email(email):
                email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
                try:
                    if not re.match(email_regex, email):
                        return False
                    return True
                except re.error as e:
                    print(f"Error in email validation regex: {e}") # Log the error
                    return False  # Or raise the exception, depending on your needs

