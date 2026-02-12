import functools
import subprocess
import urllib.parse
import re
import os

# --- Configuration ---
ALLOWED_COMMANDS = ["ping"]  # Allowlist of allowed commands
SANDBOX_ENABLED = True  # Enable or disable sandboxing (requires setup)
LOG_FILE = "ping_log.txt" # Log file for audit trail

# --- Security Functions ---

def is_valid_url(url):
    """
    Validates the URL to prevent malicious URLs.
    Checks for valid scheme, netloc, and prevents common injection attempts.
    """
    try:
        result = urllib.parse.urlparse(url)
        # Check scheme (e.g., http, https)
        if result.scheme not in ("http", "https"):
            return False

        # Check netloc (hostname)
        if not result.netloc:
            return False

        # Prevent IP address URLs (can bypass hostname checks)
        try:
            import ipaddress
            ipaddress.ip_address(result.netloc)
            return False  # Reject IP addresses
        except ValueError:
            pass  # Not an IP address

        # Check for potentially malicious characters in hostname
        if not re.match(r"^[a-zA-Z0-9.-]+$", result.netloc):
            return False

        # Check for subdomain sequences
        if result.netloc.count("..") > 0:
            return False

        return True
    except Exception:
        return False

def sanitize_url(url):
    """
    Sanitizes the URL to prevent command injection.
    This function performs URL parsing and encoding to mitigate potential risks.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        # Reconstruct the URL with encoded components
        sanitized_url = urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            urllib.parse.quote(parsed_url.path),
            urllib.parse.quote(parsed_url.params),
            urllib.parse.quote(parsed_url.query),
            urllib.parse.quote(parsed_url.fragment)
        ))
        return sanitized_url
    except Exception as e:
        print(f"Error sanitizing URL: {e}")
        return None

def run_in_sandbox(command):
    """
    Executes the command in a sandboxed environment (e.g., chroot jail, AppArmor).
    This is a placeholder and requires actual sandbox setup.
    """
    if not SANDBOX_ENABLED:
        return command  # Bypass sandboxing if disabled

    # Example using chroot (requires proper setup)
    # chroot_path = "/path/to/chroot/jail"
    # command = ["chroot", chroot_path] + command

    # Example using AppArmor (requires proper setup)
    # apparmor_profile = "ping_profile"
    # command = ["aa-exec", "-p", apparmor_profile] + command

    print("Running in sandbox (placeholder - requires actual setup)")
    return command

def log_activity(url, result):
    """Logs the ping activity for auditing."""
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"Pinged {url}: {result}\n")
    except Exception as e:
        print(f"Error logging activity: {e}")

# --- Decorator ---
def route(url_path):
    """
    Decorator to bind a function to a URL path.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # In a real web framework, this would be part of the routing mechanism.
            # For this example, we'll just check if the requested path matches.
            if url_path == "/ping":
                return func(*args, **kwargs)
            else:
                return "404 Not Found"  # Or handle the route appropriately

        return wrapper
    return decorator

# --- Application Code ---

@route("/ping")
def ping(url):
    """
    Pings the specified URL and returns the result.
    """
    if not url:
        return "Error: URL parameter is missing."

    if not is_valid_url(url):
        return "Error: Invalid URL."

    sanitized_url = sanitize_url(url)
    if not sanitized_url:
        return "Error: URL sanitization failed."

    try:
        parsed_url = urllib.parse.urlparse(sanitized_url)
        hostname = parsed_url.netloc

        # Command construction (using vetted library)
        command = ["ping", "-c", "3", hostname]  # Limit to 3 pings

        # Sandbox execution
        command = run_in_sandbox(command)

        # Execute the command using subprocess.run (safer than os.system)
        process = subprocess.run(command, capture_output=True, text=True, timeout=10)

        if process.returncode == 0:
            result = process.stdout
        else:
            result = f"Error: Ping failed with code {process.returncode}\n{process.stderr}"

        log_activity(url, result)
        return result

    except subprocess.TimeoutExpired:
        return "Error: Ping timed out."
    except FileNotFoundError:
        return "Error: Ping command not found.  Check your system configuration."
    except Exception as e:
        return f"An unexpected error occurred: {e}"

# --- Example Usage (Simulating a Web Request) ---
if __name__ == "__main__":
    # Simulate a request with a URL parameter
    test_url = "https://www.example.com"
    response = ping(test_url)
    print(response)

    test_url_malicious = "https://www.example.com; ls -l" #Malicious URL
    response = ping(test_url_malicious)
    print(response)

    test_url_ip = "http://127.0.0.1" #IP Address URL
    response = ping(test_url_ip)
    print(response)

    test_url_subdomain = "http://..example.com" #Subdomain URL
    response = ping(test_url_subdomain)
    print(response)

