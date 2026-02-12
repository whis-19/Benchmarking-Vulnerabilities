import os
import mimetypes
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
import re
import logging
from django.views.decorators.http import require_GET

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = ['.pdf', '.txt', '.jpg', '.jpeg', '.png']  # Example

BASE_DIR = "/path/to/your/file/storage"  # Define a base directory OUTSIDE your web root

def sanitize_filename(filename):
    # Remove or replace path traversal characters
    filename = re.sub(r"[^a-zA-Z0-9_\-.]", "_", filename)
    # Limit filename length
    filename = filename[:255]
    return filename.lower()

def sanitize_date(date_string):
    # Allow only YYYY-MM-DD format
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_string):
        return None  # Or raise an exception
    return date_string

@login_required
@require_GET
def getResource(request):
    username = request.user.username

    if not username.isalnum():
        logger.warning(f"Invalid username format: {username} (from authenticated user)")
        return HttpResponseBadRequest("Invalid username format.")

    filename = request.GET.get('filename')
    if not filename:
        return HttpResponseBadRequest("Filename is required.")

    date = request.GET.get('date')
    safe_date = sanitize_date(date)
    if not safe_date:
        logger.warning(f"Invalid date format: {date}")
        return HttpResponseBadRequest("Invalid date format.")


    safe_filename = sanitize_filename(filename)
    filename_without_extension, extension = os.path.splitext(safe_filename)

    if extension.lower() not in ALLOWED_EXTENSIONS:
        logger.warning(f"Invalid file extension: {extension}")
        return HttpResponseBadRequest("Invalid file extension.")

    safe_username = sanitize_filename(username) # Sanitize username for filepath

    filepath = os.path.join(BASE_DIR, safe_username, safe_date, safe_filename)
    filepath = os.path.abspath(filepath)

    if not filepath.startswith(BASE_DIR):
        logger.warning(f"Attempted path traversal: {filepath}")
        return HttpResponseBadRequest("Invalid file path.")

    try:
        with open(filepath, 'rb') as f:
            content = f.read()

        content_type, _ = mimetypes.guess_type(filepath)
        if content_type is None:
            content_type = 'application/octet-stream'  # Default

        response = HttpResponse(content, content_type=content_type)
        response['Content-Disposition'] = f'attachment; filename="{safe_filename}"'
        response['X-Content-Type-Options'] = 'nosniff'
        return response

    except FileNotFoundError:
        logger.warning(f"File not found: {filepath}")
        return HttpResponseBadRequest("File not found.")
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")
        return HttpResponse("An error occurred. Please try again later.", status=500)

