import socket
import json
import logging
import os
import secrets
import ssl
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Allowed domains/IPs for sending responses.  This MUST be strictly controlled.
ALLOWED_DOMAINS = ["example.com", "192.168.1.100"]  # Replace with your allowed domains/IPs
ALLOWED_IPS = ["127.0.0.1", "::1"] # Example IPv6 localhost

# Server certificate and key for TLS
SERVER_CERT = "server.crt"  # Replace with your server certificate path
SERVER_KEY = "server.key"  # Replace with your server key path

# Client certificate authority for TLS client authentication (optional)
CLIENT_CA = "client_ca.crt" # Replace with your client CA certificate path, or None if not using client authentication

def is_valid_ip(ip_address):
    """
    Validates if the provided IP address is in the allowed list.
    """
    try:
        socket.inet_pton(socket.AF_INET, ip_address)  # Check if it's a valid IPv4 address
        return ip_address in ALLOWED_IPS
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip_address)  # Check if it's a valid IPv6 address
            return ip_address in ALLOWED_IPS
        except socket.error:
            return False  # Not a valid IPv4 or IPv6 address

def is_valid_domain(hostname):
    """
    Validates if the provided hostname is in the allowed list.
    """
    return hostname in ALLOWED_DOMAINS

def is_valid_url(url):
    """
    Validates the URL against the allowlist.  Only allows HTTPS and allowed domains.
    """
    try:
        result = urlparse(url)
        if result.scheme != "https":
            logging.warning(f"Invalid URL scheme: {result.scheme}. Only HTTPS is allowed.")
            return False

        if result.hostname:
            if not is_valid_domain(result.hostname):
                logging.warning(f"Invalid domain: {result.hostname}. Not in allowlist.")
                return False
            return True
        else:
            logging.warning("URL missing hostname.")
            return False

    except Exception as e:
        logging.error(f"Error parsing URL: {e}")
        return False

def parse_udp_packet(data):
    """
    Parses the UDP packet data.  This is a placeholder; implement your parsing logic here.
    Crucially, validate and sanitize the data before using it.  Assume data is JSON.
    """
    try:
        # Disable entity expansion (important for security)
        # This is not directly applicable to JSON, but if you were using XML, you would disable it.
        # Example for XML (if applicable):
        # import xml.etree.ElementTree as ET
        # parser = ET.XMLParser(resolve_entities=False)
        # root = ET.fromstring(xml_data, parser=parser)

        parsed_data = json.loads(data)

        # Example validation and sanitization:
        destination_url = parsed_data.get("destination_url")
        message = parsed_data.get("message")

        if not isinstance(message, str):
            logging.warning("Invalid message format.  Expected string.")
            return None, None

        if not is_valid_url(destination_url):
            logging.warning(f"Invalid destination URL: {destination_url}")
            return None, None

        # Sanitize the message (example: limit length)
        sanitized_message = message[:200]  # Limit to 200 characters

        return destination_url, sanitized_message

    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON: {e}")
        return None, None
    except Exception as e:
        logging.error(f"Error parsing UDP packet: {e}")
        return None, None

def send_response(destination_url, data):
    """
    Sends the response to the specified destination URL using HTTPS.
    """
    try:
        # Validate the URL again before sending (double-check)
        if not is_valid_url(destination_url):
            logging.warning(f"Invalid destination URL (again): {destination_url}")
            return

        # Extract hostname and path from the URL
        parsed_url = urlparse(destination_url)
        hostname = parsed_url.hostname
        path = parsed_url.path if parsed_url.path else "/"
        port = 443  # HTTPS default port

        # Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Wrap the socket with SSL/TLS
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(CLIENT_CA) # Verify the server's certificate against the client CA
        context.check_hostname = True  # Ensure the hostname matches the certificate
        context.verify_mode = ssl.CERT_REQUIRED  # Require certificate verification

        secure_sock = context.wrap_socket(sock, server_hostname=hostname)

        # Connect to the server
        secure_sock.connect((hostname, port))

        # Construct the HTTP request
        request = f"POST {path} HTTP/1.1\r\n"
        request += f"Host: {hostname}\r\n"
        request += "Content-Type: application/json\r\n"
        request += f"Content-Length: {len(data.encode())}\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"
        request += data

        # Send the request
        secure_sock.sendall(request.encode())

        # Receive the response (optional - handle as needed)
        response = secure_sock.recv(4096)
        logging.info(f"Response from server: {response.decode()}")

    except ssl.SSLError as e:
        logging.error(f"SSL Error: {e}")
    except socket.gaierror as e:
        logging.error(f"Socket error (name resolution): {e}")
    except Exception as e:
        logging.error(f"Error sending response: {e}")
    finally:
        if secure_sock:
            secure_sock.close()

def sendData():
    """
    Creates a UDP socket and continuously receives UDP packets, parses them, and sends responses.
    """
    UDP_IP = "127.0.0.1"  # Listen on all interfaces
    UDP_PORT = 5005

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    logging.info(f"Listening for UDP packets on {UDP_IP}:{UDP_PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(1024)  # Buffer size is 1024 bytes
            logging.info(f"Received message from {addr}: {data.decode()}")

            destination_url, message = parse_udp_packet(data.decode())

            if destination_url and message:
                send_response(destination_url, json.dumps({"message": message})) # Send as JSON
            else:
                logging.warning("Failed to parse UDP packet or invalid data.")

        except Exception as e:
            logging.error(f"Error receiving or processing UDP packet: {e}")

if __name__ == "__main__":
    sendData()

