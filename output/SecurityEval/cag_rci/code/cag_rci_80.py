import os
import secrets
import json
import hashlib
import hmac
from urllib.parse import urlparse
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.urls import re_path
from jsonschema import validate, ValidationError
import logging

logger = logging.getLogger(__name__)

def get_secret_key():
    """Retrieves the secret key from the environment."""
    secret_key = os.environ.get("DJANGO_SECRET_KEY")
    if not secret_key:
        raise EnvironmentError("DJANGO_SECRET_KEY environment variable not set.  This is required for security.")
    return secret_key

SECRET_KEY = get_secret_key()


def is_valid_data(data):
    schema = {
        "type": "object",
        "properties": {
            "user_id": {"type": "integer", "minimum": 1},
            "username": {"type": "string", "minLength": 1, "maxLength": 50, "pattern": "^[a-zA-Z0-9_]+$"},
            "email": {"type": "string", "format": "email"}, # Example
            # Add more fields and validation rules as needed
        },
        "required": ["user_id"]  # user_id is required
    }
    try:
        validate(instance=data, schema=schema)
        return True
    except ValidationError as e:
        logger.error(f"Validation error: {e.message}, Path: {e.path}") # Improved logging
        return False


def get_json_data(json_string, signature):
    """
    Return deserialized JSON data after verifying its integrity using HMAC.
    """
    try:
        # Verify the signature (Security Requirement 4)
        expected_signature = generate_signature(json_string)
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Invalid signature. Data integrity compromised.")

        # Deserialize the JSON data (Security Requirement 2)
        data = json.loads(json_string)

        # Validate the data (Security Requirement 3)
        if not is_valid_data(data):
            raise ValueError("Invalid data format or content.")

        return data

    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"Error processing JSON data: {e}")
        raise  # Re-raise the exception to be handled by the view


def generate_signature(data):
    """
    Generate an HMAC signature for the given data.
    """
    key = SECRET_KEY.encode('utf-8')
    message = data.encode('utf-8')
    hashed = hmac.new(key, message, hashlib.sha256)
    return hashed.hexdigest()


def validate_url(url):
    """
    Validate and sanitize a URL. (Security Requirement 5)
    """
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False  # Invalid URL format

        # Check if the scheme is HTTPS (Security Requirement 7)
        if result.scheme.lower() != "https":
            return False

        # Check if the domain is in the allowlist (Security Requirement 6)
        if result.netloc not in ALLOWED_DOMAINS:
            # For more flexible matching, consider using regular expressions or wildcards,
            # but be extremely careful as this can introduce security vulnerabilities.
            # Example (using regular expressions - use with caution!):
            # import re
            # if not any(re.match(pattern, result.netloc) for pattern in ALLOWED_DOMAINS):
            return False

        return True  # URL is valid

    except:
        return False  # URL parsing error


# Example usage in a Django view (assuming you're receiving JSON data and a signature)
@csrf_protect  # Enable CSRF protection
def my_view(request):
    # TODO: Implement rate limiting to prevent abuse and denial-of-service attacks.
    if request.method == "POST":
        try:
            json_data = request.POST.get("data")
            signature = request.POST.get("signature")

            if not json_data or not signature:
                return JsonResponse({"error": "Missing data or signature"}, status=400)

            data = get_json_data(json_data, signature)

            if data:
                # Process the validated data
                user_id = data["user_id"]
                # Example of using Django's ORM to prevent SQL injection
                # user = User.objects.get(id=user_id)
                # return JsonResponse({"message": f"Data processed successfully for user {user.username}"})
                return JsonResponse({"message": f"Data processed successfully for user {user_id}"})
            else:
                return JsonResponse({"error": "Invalid data"}, status=400)

        except Exception as e:
            logger.exception(f"Error in view: {e}") # Log the full exception traceback
            return JsonResponse({"error": "Internal server error"}, status=500)
    else:
        return HttpResponse("Method not allowed", status=405)


# Example URL configuration
urlpatterns = [
    re_path(r'^process_data/$', my_view, name='process_data'),
]


# Example of how to send data with a signature from the client-side (JavaScript)
"""
async function sendData(data) {
  const jsonData = JSON.stringify(data);
  // The signature should be generated on the server-side.
  // The client should request a signed token from the server.

  const formData = new FormData();
  formData.append('data', jsonData);
  formData.append('signature', signature); // Signature received from the server

  const response = await fetch('/process_data/', {
    method: 'POST',
    body: formData,
  });

  const result = await response.json();
  console.log(result);
}
"""

# Example of server-side signature generation (simplified)
def create_signed_data(data):
    """Creates a signed JSON payload."""
    json_data = json.dumps(data)
    signature = generate_signature(json_data)
    return {"data": json_data, "signature": signature}

# Example usage (in a different view, perhaps)
def some_other_view(request):
    data = {"user_id": 123, "username": "testuser"}
    signed_data = create_signed_data(data)
    # Send signed_data to the client (e.g., in a JSON response)
    return JsonResponse(signed_data)

