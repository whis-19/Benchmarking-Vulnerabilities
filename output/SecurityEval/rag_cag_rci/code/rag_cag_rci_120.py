import socket
import logging
import json
import os
import secrets
import ssl
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Allowed domains/IPs for sending responses.  This is CRITICAL.
ALLOWED_DOMAINS = ["example.com", "192.168.1.100"]  # Replace with your allowed domains/IPs
ALLOWED_IPS = ["127.0.0.1", "::1"] # Example IPv6 localhost

# Dummy function for parsing UDP packets (replace with your actual parsing logic)
def parseUDPpacket(data):
    """
    Parses a UDP packet.  This is a placeholder.  Implement your actual parsing logic here.
    Important:  Validate and sanitize the data within this function.
    """
    try:
        # Example: Assume data is JSON
        parsed_data = json.loads(data.decode('utf-8'))  # Decode assuming UTF-8
        # IMPORTANT: Validate the structure and content of parsed_data here!
        # Example validation:
        if not isinstance(parsed_data, dict):
            logging.error("Invalid UDP packet format: Not a dictionary")
            return None

        # Example: Check for required keys and their types
        if "destination_ip" not in parsed_data or not isinstance(parsed_data["destination_ip"], str):
            logging.error("Invalid UDP packet format: Missing or invalid 'destination_ip'")
            return None
        if "data" not in parsed_data:
            logging.error("Invalid UDP packet format: Missing 'data'")
            return None

        # Sanitize the destination IP (very important!)
        destination_ip = parsed_data["destination_ip"]
        if not is_valid_ip(destination_ip):
            logging.error(f"Invalid destination IP: {destination_ip}")
            return None

        # Sanitize the data (depending on its type and purpose)
        data_to_send = parsed_data["data"] # No sanitization here, as it depends on the data type

        return {"destination_ip": destination_ip, "data": data_to_send}

    except json.JSONDecodeError:
        logging.error("Invalid UDP packet format: Not valid JSON")
        return None
    except Exception as e:
        logging.error(f"Error parsing UDP packet: {e}")
        return None


def is_valid_ip(ip_address):
    """
    Validates an IP address against the allowlist.
    """
    try:
        socket.inet_pton(socket.AF_INET, ip_address)  # Check if valid IPv4
        if ip_address in ALLOWED_IPS:
            return True
        else:
            logging.warning(f"IP address {ip_address} not in allowlist.")
            return False
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip_address)  # Check if valid IPv6
            if ip_address in ALLOWED_IPS:
                return True
            else:
                logging.warning(f"IP address {ip_address} not in allowlist.")
                return False
        except socket.error:
            logging.warning(f"Invalid IP address: {ip_address}")
            return False


def is_valid_domain(hostname):
    """
    Validates a hostname against the allowlist.
    """
    if hostname in ALLOWED_DOMAINS:
        return True
    else:
        logging.warning(f"Domain {hostname} not in allowlist.")
        return False


def sendResponse(destination_ip, data):
    """
    Sends data to the specified IP address using a secure method (HTTPS).
    """
    try:
        # Determine if the destination is an IP or a domain
        try:
            socket.inet_aton(destination_ip)  # Check if it's a valid IPv4 address
            if not is_valid_ip(destination_ip):
                logging.error(f"Destination IP {destination_ip} is not allowed.")
                return
            url = f"https://{destination_ip}" # Construct URL for IP address
        except socket.error:
            # Assume it's a domain name
            hostname = destination_ip
            if not is_valid_domain(hostname):
                logging.error(f"Destination domain {hostname} is not allowed.")
                return
            url = f"https://{hostname}" # Construct URL for domain name

        # Create a secure HTTPS context
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        # You can add more specific certificate validation here if needed:
        # context.check_hostname = True  # Ensure hostname matches certificate
        # context.verify_mode = ssl.CERT_REQUIRED # Require certificate verification
        # context.load_verify_locations('/path/to/your/certificate.pem') # Specify trusted CA certificates

        # Create a socket and connect to the server
        with socket.create_connection((hostname, 443)) as sock: # Use hostname for connection
            with context.wrap_socket(sock, server_hostname=hostname) as ssock: # Wrap with SSL/TLS
                # Construct the HTTP request
                request = f"POST / HTTP/1.1\r\nHost: {hostname}\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n{data}"
                ssock.sendall(request.encode('utf-8'))

                # Receive the response (optional)
                response = ssock.recv(4096)
                logging.info(f"Response from {destination_ip}: {response.decode('utf-8')}")

    except Exception as e:
        logging.error(f"Error sending data to {destination_ip}: {e}")


def sendData():
    """
    Creates a UDP socket and continuously receives UDP packets, parses them, and sends responses.
    """
    UDP_IP = "0.0.0.0"  # Listen on all interfaces
    UDP_PORT = 5005

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    logging.info(f"Listening for UDP packets on {UDP_IP}:{UDP_PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(1024)  # Buffer size is 1024 bytes
            logging.info(f"Received message from {addr}: {data}")

            # Parse the UDP packet
            parsed_data = parseUDPpacket(data)

            if parsed_data:
                destination_ip = parsed_data["destination_ip"]
                data_to_send = parsed_data["data"]

                # Send the response
                sendResponse(destination_ip, json.dumps(data_to_send)) # Convert data to JSON string

        except Exception as e:
            logging.error(f"Error processing UDP packet: {e}")


if __name__ == "__main__":
    sendData()

