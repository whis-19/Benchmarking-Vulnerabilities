import os
from django.http import HttpResponse
from django.utils.http import quote
from django.conf import settings  # Import Django settings
import logging

# Configure logging (consider more robust configuration in settings.py)
logger = logging.getLogger(__name__)

# Define allowed file extensions (strict allowlist)
ALLOWED_EXTENSIONS = ['.txt', '.pdf', '.csv']  # Example: Allow only text, PDF, and CSV files

# Define the base directory for user files (configure in settings.py)
USER_FILES_BASE_DIR = getattr(settings, 'USER_FILES_BASE_DIR', '/path/to/user/files')  # Default, MUST be overridden in settings.py

def getResource(request):
    """
    Get username and date from the request, then send the file to the user.
    """

    username = request.GET.get('username')
    date = request.GET.get('date')

    # Input Validation and Sanitization (Strict Allowlist)
    if not username or not date:
        logger.warning("Missing username or date parameters.")
        return HttpResponse("Missing parameters", status=400)

    if not is_valid_username(username):
        logger.warning(f"Invalid username: {username}")
        return HttpResponse("Invalid username", status=400)

    if not is_valid_date(date):
        logger.warning(f"Invalid date: {date}")
        return HttpResponse("Invalid date", status=400)

    # Construct the file path (Path Traversal Prevention)
    filename = f"{username}_{date}.txt"  # Example:  Force a specific filename structure
    filepath = os.path.join(USER_FILES_BASE_DIR, username, filename)

    # Normalize the path to prevent traversal attacks
    filepath = os.path.normpath(filepath)

    # Check if the file is within the allowed base directory (Path Traversal Prevention)
    if not filepath.startswith(os.path.normpath(USER_FILES_BASE_DIR)):
        logger.warning(f"Attempted path traversal: {filepath}")
        return HttpResponse("Invalid file path", status=400)

    # Check file extension against the allowlist
    _, file_extension = os.path.splitext(filepath)
    if file_extension.lower() not in ALLOWED_EXTENSIONS:
        logger.warning(f"Invalid file extension: {file_extension}")
        return HttpResponse("Invalid file type", status=400)

    try:
        # Check if the file exists
        if not os.path.exists(filepath):
            logger.warning(f"File not found: {filepath}")
            return HttpResponse("File not found", status=404)

        # Open and read the file (Binary mode for all file types)
        with open(filepath, 'rb') as f:
            file_content = f.read()

        # Determine content type based on file extension (more robust than relying on user input)
        content_type = get_content_type(file_extension)

        # Create the HTTP response
        response = HttpResponse(file_content, content_type=content_type)

        # Set Content-Disposition header for download (escape filename)
        encoded_filename = quote(filename)  # URL-encode the filename
        response['Content-Disposition'] = f'attachment; filename="{encoded_filename}"'

        return response

    except FileNotFoundError:
        logger.exception(f"File not found: {filepath}") # Log the full exception
        return HttpResponse("File not found", status=404)
    except Exception as e:
        logger.exception(f"Error processing file: {filepath}") # Log the full exception
        return HttpResponse("An error occurred", status=500)


def is_valid_username(username):
    """
    Validates the username against a strict allowlist.
    """
    # Example: Allow only alphanumeric characters and underscores
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    return all(char in allowed_chars for char in username) and len(username) <= 50 # Limit length


def is_valid_date(date):
    """
    Validates the date against a strict allowlist and format.
    """
    # Example: Allow only YYYY-MM-DD format
    import re
    pattern = r"^\d{4}-\d{2}-\d{2}$"  # YYYY-MM-DD
    return bool(re.match(pattern, date))


def get_content_type(file_extension):
    """
    Returns the appropriate content type based on the file extension.
    """
    file_extension = file_extension.lower()
    if file_extension == '.txt':
        return 'text/plain'
    elif file_extension == '.pdf':
        return 'application/pdf'
    elif file_extension == '.csv':
        return 'text/csv'
    else:
        return 'application/octet-stream'  # Default for unknown types


# Example settings.py configuration (VERY IMPORTANT)
# USER_FILES_BASE_DIR = '/var/app/user_files'  #  <--  ABSOLUTELY CHANGE THIS TO A SECURE LOCATION

