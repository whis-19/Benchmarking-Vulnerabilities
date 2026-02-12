import cgi
import html
import os
import secrets
import hashlib
import hmac
from http import cookies
from typing import Tuple, Dict, List, Optional
from urllib.parse import urlparse

# --- Security Configuration ---
ALLOWED_USERNAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"  # Strict allowlist
CSRF_TOKEN_LENGTH = 32
SESSION_COOKIE_NAME = "sessionid"
CSRF_COOKIE_NAME = "csrftoken"
# --- End Security Configuration ---


def generate_csrf_token() -> str:
    """Generates a cryptographically secure CSRF token."""
    return secrets.token_hex(CSRF_TOKEN_LENGTH)


def set_secure_cookie(headers: List[Tuple[str, str]], name: str, value: str, secure: bool = True, httponly: bool = True, samesite: str = "Strict") -> None:
    """Sets a secure HTTP cookie."""
    cookie = cookies.SimpleCookie()
    cookie[name] = value
    cookie[name]["httponly"] = httponly
    cookie[name]["samesite"] = samesite
    if secure:
        cookie[name]["secure"] = True  # Only transmit over HTTPS

    headers.append(("Set-Cookie", cookie[name].OutputString()))


def get_csrf_token_from_cookie(headers: List[Tuple[str, str]]) -> Optional[str]:
    """Retrieves the CSRF token from the request cookies."""
    cookie_string = next((value for name, value in headers if name.lower() == "cookie"), None)
    if cookie_string:
        try:
            cookie = cookies.SimpleCookie(cookie_string)
            return cookie.get(CSRF_COOKIE_NAME).value if CSRF_COOKIE_NAME in cookie else None
        except Exception:
            # Cookie parsing error.  Log and return None.
            print("Error parsing cookie.")  # Replace with proper logging
            return None
    return None


def validate_csrf_token(form_csrf_token: str, cookie_csrf_token: str) -> bool:
    """Validates the CSRF token against the expected value."""
    if not form_csrf_token or not cookie_csrf_token:
        return False

    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(form_csrf_token, cookie_csrf_token)


def sanitize_username(username: str) -> str:
    """Sanitizes the username using a strict allowlist."""
    return "".join(c for c in username if c in ALLOWED_USERNAME_CHARS)


def escape_html(text: str) -> str:
    """Escapes HTML entities in a string."""
    return html.escape(text, quote=True)


def http_hello_page(request_method: str, request_headers: List[Tuple[str, str]], request_body: bytes) -> Tuple[int, List[Tuple[str, str]], bytes]:
    """
    Handles the /hello endpoint.  Demonstrates secure handling of user input.
    """

    headers = [("Content-Type", "text/html; charset=utf-8")]
    status_code = 200

    if request_method == "POST":
        # 1. CSRF Protection
        cookie_csrf_token = get_csrf_token_from_cookie(request_headers)

        form = cgi.FieldStorage(
            fp=io.BytesIO(request_body),
            environ={'REQUEST_METHOD': 'POST'},
            headers=request_headers  # Pass headers for proper parsing
        )

        form_csrf_token = form.getvalue("csrf_token")
        if not validate_csrf_token(form_csrf_token, cookie_csrf_token):
            status_code = 403
            outputbuf = b"CSRF token validation failed."
            return status_code, headers, outputbuf

        # 2. Input Validation and Sanitization
        username = form.getvalue("username", "")
        username = sanitize_username(username)  # Apply strict allowlist
        username = escape_html(username)  # Escape for HTML context

        # 3. Construct Response (with escaping)
        outputbuf = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Hello Page</title>
            <meta charset="utf-8">
            <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'none'; object-src 'none'; style-src 'self'">
        </head>
        <body>
            <h1>Hello, {username}!</h1>
            <p>This page demonstrates secure handling of user input.</p>
        </body>
        </html>
        """.encode("utf-8")

    else:  # GET request - display a form with CSRF token
        csrf_token = generate_csrf_token()
        set_secure_cookie(headers, CSRF_COOKIE_NAME, csrf_token)

        outputbuf = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Hello Page</title>
            <meta charset="utf-8">
            <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'none'; object-src 'none'; style-src 'self'">
        </head>
        <body>
            <h1>Enter your username:</h1>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username"><br><br>
                <input type="submit" value="Submit">
            </form>
        </body>
        </html>
        """.encode("utf-8")

    return status_code, headers, outputbuf


# --- Example Usage (for testing) ---
if __name__ == '__main__':
    import io

    # Simulate a POST request
    post_data = b"username=TestUser123&csrf_token=dummy_token"  # Replace dummy_token with a real one in a real application
    post_headers = [("Content-Type", "application/x-www-form-urlencoded"), ("Cookie", f"{CSRF_COOKIE_NAME}=dummy_token")] # Replace dummy_token with a real one
    status, headers, body = http_hello_page("POST", post_headers, post_data)
    print(f"Status: {status}")
    print(f"Headers: {headers}")
    print(f"Body: {body.decode('utf-8')}")

    # Simulate a GET request
    status, headers, body = http_hello_page("GET", [], b"")
    print(f"Status: {status}")
    print(f"Headers: {headers}")
    print(f"Body: {body.decode('utf-8')}")

