import shlex
import subprocess
import re
import socket  # For DNS resolution (optional)
import time

def is_valid_hostname(hostname):
    """
    Validates a hostname based on a strict whitelist of characters and format.
    This is a *critical* security measure.

    Length limits prevent buffer overflows and DoS attacks.
    The regex validates the hostname format: alphanumeric segments separated by dots,
    preventing injection of unexpected characters.
    """
    if not (1 <= len(hostname) <= 253):  # Enforce length limits
        return False

    # Allow alphanumeric characters, hyphens, and dots.  Must start and end with alphanumeric.
    # The '61' represents the maximum length of a label in a domain name.
    pattern = r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    if not re.match(pattern, hostname):
        return False

    return True

def resolve_hostname(hostname):
    """
    Attempts to resolve the hostname to an IP address.  This is optional but
    recommended to prevent pinging internal or malicious addresses.

    Be aware that DNS resolution can be spoofed (DNS poisoning).  Even if the
    initial resolution is to a safe IP, a compromised DNS resolver could later
    return a malicious IP for the same hostname.  Consider using DNSSEC if available.

    DNS resolution itself can be a source of information disclosure, revealing
    the hostnames being accessed to network observers.
    """
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False

def check_port_open(hostname, port, timeout=5):
    """Checks if a port is open on a given hostname using a socket connection.
    This is an alternative to using the ping command.  Even with sockets,
    hostname validation is crucial.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((hostname, port))
            return True
    except (socket.timeout, socket.error) as e:
        print(f"Socket error: {e}") # Log the specific error
        return False

def is_rate_limited(user_id, requests_per_minute=10):
    """
    Basic rate limiting implementation.  Replace with a more robust solution
    for production environments (e.g., using Redis or a database).
    """
    global request_counts  # Use a global dictionary for simplicity (not thread-safe!)
    if user_id not in request_counts:
        request_counts[user_id] = []

    now = time.time()
    # Remove requests older than 1 minute
    request_counts[user_id] = [t for t in request_counts[user_id] if t > now - 60]

    if len(request_counts[user_id]) >= requests_per_minute:
        return True  # Rate limited

    request_counts[user_id].append(now)
    return False  # Not rate limited

def ping_host(hostname, user_id="anonymous"):
    """
    Pings a host after thorough validation and rate limiting.
    """

    if is_rate_limited(user_id):
        print("Error: Rate limit exceeded.")
        return None

    if not is_valid_hostname(hostname):
        print("Error: Invalid hostname.")
        return None  # Or raise an exception

    # Optional: Resolve the hostname to an IP address
    if not resolve_hostname(hostname):
        print("Error: Could not resolve hostname.")
        return None

    sanitized_hostname = shlex.quote(hostname)

    try:
        result = subprocess.run(
            ["ping", "-c", "1", sanitized_hostname],
            capture_output=True,  # Capture output for logging/analysis
            text=True,           # Decode output as text
            timeout=10,          # Prevent indefinite hanging
            check=True,          # Raise an exception on non-zero exit code
            shell=False          # VERY IMPORTANT: Disable shell interpretation
        )

        print(f"Ping output: {result.stdout}")
        # Log successful ping
        log_message = f"User: {user_id}, Hostname: {hostname}, IP: (resolved IP), Result: Success" # Add resolved IP
        print(log_message) # Replace with proper logging

        return result.stdout

    except subprocess.CalledProcessError as e:
        print(f"Error: Ping failed with exit code {e.returncode}")
        print(f"Error output: {e.stderr}")
        # Log failed ping
        log_message = f"User: {user_id}, Hostname: {hostname}, IP: (resolved IP), Result: Failure, Error: {e.stderr}" # Add resolved IP
        print(log_message) # Replace with proper logging
        return None
    except subprocess.TimeoutExpired:
        print("Error: Ping timed out.")
        # Log timeout
        log_message = f"User: {user_id}, Hostname: {hostname}, IP: (resolved IP), Result: Timeout" # Add resolved IP
        print(log_message) # Replace with proper logging
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        # Log unexpected error
        log_message = f"User: {user_id}, Hostname: {hostname}, IP: (resolved IP), Result: Unexpected Error: {e}" # Add resolved IP
        print(log_message) # Replace with proper logging
        return None

# Global dictionary for rate limiting (not thread-safe!)
request_counts = {}

# Example usage:
user_provided_hostname = "example.com"  # Replace with user input
ping_result = ping_host(user_provided_hostname, user_id="user123")

if ping_result:
    print("Ping successful.")
else:
    print("Ping failed.")

# Example using socket:
if check_port_open(user_provided_hostname, 80):
    print(f"{user_provided_hostname}:80 is reachable using socket")
else:
    print(f"{user_provided_hostname}:80 is not reachable using socket")

