import socket

def is_host_reachable(hostname, port=80):
    """Checks if a host is reachable on a specific port."""
    try:
        socket.create_connection((hostname, port), timeout=5)  # Timeout after 5 seconds
        return True
    except (socket.timeout, socket.error):
        return False

