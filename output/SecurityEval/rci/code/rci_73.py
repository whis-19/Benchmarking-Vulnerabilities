import os
import mimetypes
import logging
import uuid  # Import the uuid module
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseNotFound, HttpResponseBadRequest, HttpResponseServerError, FileResponse
from django.utils import safe_string
from django.conf import settings  # Import Django settings
from django.utils.encoding import smart_str
from django.views.decorators.csrf import csrf_exempt  # Consider CSRF protection
from django.contrib.auth.decorators import login_required # Uncomment to enable authentication
from django.shortcuts import get_object_or_404
from .models import FileModel  # Import your FileModel

logger = logging.getLogger(__name__)


@csrf_exempt  # Consider CSRF protection based on your use case
@login_required # Uncomment to enable authentication
def getResource(request, file_uuid):
    """
    Get the file UUID from the URL, retrieve the file metadata from the database,
    perform authorization checks, and then send the file to the user.

    Security Considerations:

    1.  **UUID Filenames:**  Uses UUIDs for filenames to prevent unauthorized
        access through predictable filenames.  UUIDs are generated when the file
        is created/uploaded and stored in the database along with the file
        metadata.  The URL only exposes the UUID.

    2.  **Database Integration:**  Requires a database to map the UUID to the
        actual file and its metadata.  The `FileModel` stores the UUID,
        original filename, user, upload date, file path, and content type.
        The `getResource` function queries the database using the UUID from the URL.

    3.  **Authentication and Authorization:**  Uses Django's built-in
        authentication (`@login_required`) to verify the user's identity.
        Implements authorization checks to ensure the user has permission to
        access the requested file.  This example checks if the user owns the file.

    4.  **Path Traversal Prevention:**  The file path is retrieved from the
        database, preventing path traversal attacks.  The code does *not*
        construct the file path from user input.

    5.  **Content Type Handling:**  The content type is retrieved from the
        database, preventing potential security issues related to incorrect
        content interpretation by the browser.

    6.  **File Size Limits:**  Checks the file size against a maximum allowed
        size (defined in `settings.MAX_FILE_SIZE`) to prevent denial-of-service
        attacks.

    7.  **CSRF Protection:**  The `@csrf_exempt` decorator is used.  Carefully
        consider if this is appropriate for your use case.  If the view modifies
        data, you should implement proper CSRF protection.  Remove this decorator if you need CSRF protection and ensure your form includes the CSRF token.

    8.  **Logging:**  Implements logging to track file access attempts,
        especially failed attempts, for security auditing.  Uses Django's
        built-in logging framework.

    9.  **Secure File Storage:**  Ensure that the files are stored in a secure
        location with appropriate permissions to prevent unauthorized access.

    10. **Regular Security Audits:**  Conduct regular security audits of your
         code and infrastructure to identify and address potential vulnerabilities.

    11. **Rate Limiting:**  Implement rate limiting to prevent DoS attacks.
         Consider using Django middleware or a dedicated rate-limiting library.
         # Rate Limiting:  Implement rate limiting to prevent DoS attacks.
         # Consider using Django middleware or a dedicated rate-limiting library.

    Args:
        request: The Django request object.
        file_uuid: The UUID of the file.

    Returns:
        An HttpResponse object containing the file, or an appropriate error
        response.
    """

    try:
        # Retrieve the FileModel instance from the database using the UUID
        file_object = get_object_or_404(FileModel, uuid=file_uuid)

        # Authorization Check: Does the user have permission to access this file?
        if file_object.user != request.user:  # Example authorization check
            logger.warning(f"Unauthorized access attempt: user={request.user}, file_uuid={file_uuid}")
            return HttpResponseForbidden("You do not have permission to access this file.")

        # Construct the file path
        file_path = file_object.file_path  # Get the file path from the database

        # Check file size (example)
        file_size = os.path.getsize(file_path)
        if file_size > settings.MAX_FILE_SIZE:  # Define MAX_FILE_SIZE in settings.py
            logger.warning(f"File size exceeds limit: {file_size} bytes")
            return HttpResponseBadRequest("File size exceeds the maximum allowed size.")

        # Determine the content type
        content_type = file_object.content_type # Get content type from the database
        if content_type is None:
            content_type = 'application/octet-stream'  # Default content type

        # Open and read the file
        with open(file_path, 'rb') as f:  # Open in binary mode
            # Create the HTTP response
            response = FileResponse(f, content_type=content_type) # Use FileResponse for better performance with large files

            # Content-Disposition: attachment forces download, inline attempts to display in browser.
            # `attachment` forces a download, while `inline` attempts to display the file in the browser.
            # Be aware of potential XSS risks with `inline` if the file content is not properly sanitized.
            # Browser behavior can vary depending on the file type and browser settings.
            response['Content-Disposition'] = f'attachment; filename="{smart_str(file_object.original_filename)}"'  # Force download

            return response

    except FileNotFoundError:
        logger.warning(f"File not found: file_uuid={file_uuid}, file_path={file_path}")
        return HttpResponseNotFound("File not found.")
    except PermissionError:
        logger.warning(f"Permission denied: user={request.user}, file_uuid={file_uuid}, file_path={file_path}")
        return HttpResponseForbidden("You do not have permission to access this file.")
    except Exception as e:
        logger.error(f"Error processing file: user={request.user}, file_uuid={file_uuid}, file_path={file_path}, error={e}", exc_info=True)
        return HttpResponseServerError("An error occurred while processing the file.")


# Example FileModel (models.py)
from django.db import models
from django.contrib.auth.models import User
import uuid

class FileModel(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    original_filename = models.CharField(max_length=255)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    upload_date = models.DateTimeField(auto_now_add=True)
    file_path = models.CharField(max_length=255)  # Store the actual file path
    content_type = models.CharField(max_length=255, blank=True, null=True) # Store the content type

    def __str__(self):
        return self.original_filename

# Example AppConfig.ready() (apps.py)
from django.apps import AppConfig
from django.core.exceptions import ImproperlyConfigured

class YourAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'your_app'

    def ready(self):
        # Settings Validation
        if not hasattr(settings, 'ALLOWED_FILE_DIRECTORY'):
            raise ImproperlyConfigured("ALLOWED_FILE_DIRECTORY must be defined in settings.py")
        if not os.path.isdir(settings.ALLOWED_FILE_DIRECTORY):
            raise ImproperlyConfigured("ALLOWED_FILE_DIRECTORY must be a valid directory")

