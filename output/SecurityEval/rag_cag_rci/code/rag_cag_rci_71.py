import socket
import struct
import random
import hashlib
import time

# Allowed domains/IPs (allowlist)
ALLOWED_DOMAINS = ["example.com", "example.net"]
ALLOWED_IPS = ["127.0.0.1", "192.168.1.1"]  # Example private IPs

# Secret key for checksumming (rotate regularly)
SECRET_KEY = b"ThisIsASecretKey"

def is_valid_domain(domain):
    """Validates if a domain is in the allowlist."""
    return domain in ALLOWED_DOMAINS

def is_valid_ip(ip_address):
    """Validates if an IP address is in the allowlist."""
    return ip_address in ALLOWED_IPS

def parseUDPpacket(data):
    """
    Parses a UDP packet containing a DNS request.  Performs basic validation.
    """
    try:
        # Basic sanity check: minimum DNS packet size
        if len(data) < 12:
            print("Error: Packet too short.")
            return None, None

        # Extract transaction ID (first 2 bytes)
        transaction_id = struct.unpack("!H", data[:2])[0]

        # Extract flags (next 2 bytes) - basic check for recursion desired
        flags = struct.unpack("!H", data[2:4])[0]
        recursion_desired = (flags >> 8) & 1  # Check RD bit

        # Further parsing logic would go here to extract the domain name,
        # query type, and query class.  This is a simplified example.
        # In a real implementation, you'd need to handle variable-length
        # domain names and different query types.

        # For now, assume the domain name is at offset 12 and is null-terminated.
        domain_start = 12
        domain_end = data.find(b'\x00', domain_start)
        if domain_end == -1:
            print("Error: Invalid domain name format.")
            return None, None

        domain_name = data[domain_start:domain_end].decode("utf-8", "ignore")  # Decode safely

        # Validate the domain name
        if not is_valid_domain(domain_name):
            print(f"Error: Domain {domain_name} is not allowed.")
            return None, None

        return transaction_id, domain_name

    except Exception as e:
        print(f"Error parsing UDP packet: {e}")
        return None, None


def resolveName(nameToResolve):
    """
    Resolves a domain name to an IP address.  This is a placeholder.
    In a real implementation, you would perform a DNS lookup.
    """
    if not is_valid_domain(nameToResolve):
        print(f"Error: Domain {nameToResolve} is not allowed.")
        return None

    # Placeholder: Return a dummy IP address for allowed domains
    if nameToResolve == "example.com":
        return "93.184.216.34"  # Example IP
    elif nameToResolve == "example.net":
        return "192.0.43.10"  # Example IP
    else:
        return None


def sendResponse(requestIP, transaction_id, record):
    """
    Sends a DNS response back to the requesting IP address.
    Includes a checksum to prevent replay attacks.
    """
    if not is_valid_ip(requestIP):
        print(f"Error: IP address {requestIP} is not allowed.")
        return

    try:
        # Construct the DNS response packet (simplified)
        # This is a very basic example and needs to be expanded for a real DNS server.
        response = struct.pack("!H", transaction_id)  # Transaction ID
        response += struct.pack("!H", 0x8180)  # Flags: Response, Authoritative, Recursion Available
        response += struct.pack("!H", 0x0001)  # 1 Question
        response += struct.pack("!H", 0x0001)  # 1 Answer
        response += struct.pack("!H", 0x0000)  # 0 Authority records
        response += struct.pack("!H", 0x0000)  # 0 Additional records

        # Add the query (assuming it's the same as the request) - needs proper encoding
        # In a real implementation, you'd need to re-encode the domain name.
        response += b'\x07example\x03com\x00' # Example domain encoding
        response += struct.pack("!H", 0x0001)  # Type A
        response += struct.pack("!H", 0x0001)  # Class IN

        # Add the answer
        response += b'\xc0\x0c'  # Pointer to the domain name in the query
        response += struct.pack("!H", 0x0001)  # Type A
        response += struct.pack("!H", 0x0001)  # Class IN
        response += struct.pack("!I", 0x00000078)  # TTL (120 seconds)
        response += struct.pack("!H", 0x0004)  # Data length (4 bytes for IPv4)

        # Convert IP address to packed bytes
        ip_address_bytes = socket.inet_aton(record)
        response += ip_address_bytes

        # Add checksum to prevent replay attacks
        timestamp = int(time.time())
        checksum = calculate_checksum(transaction_id, record, timestamp)
        response += struct.pack("!I", timestamp)  # Add timestamp
        response += checksum

        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(response, (requestIP, 53))  # Send to port 53 (DNS)
        sock.close()

    except Exception as e:
        print(f"Error sending response: {e}")


def calculate_checksum(transaction_id, record, timestamp):
    """Calculates a checksum to prevent replay attacks."""
    data = struct.pack("!H", transaction_id) + record.encode('utf-8') + struct.pack("!I", timestamp) + SECRET_KEY
    return hashlib.sha256(data).digest()[:4]  # Use first 4 bytes of SHA256


def verify_checksum(transaction_id, record, timestamp, received_checksum):
    """Verifies the checksum of a received message."""
    expected_checksum = calculate_checksum(transaction_id, record, timestamp)
    return expected_checksum == received_checksum


def UDPMessaging(udp_ip, udp_port):
    """
    Creates a UDP socket that listens on the IP and port provided for DNS requests.
    Parses the received data, and sends back the DNS record to the requested IP in the packet.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((udp_ip, udp_port))

        print(f"Listening on {udp_ip}:{udp_port}")

        while True:
            data, addr = sock.recvfrom(1024)  # Buffer size is 1024 bytes
            requestIP = addr[0]

            # Validate the source IP address
            if not is_valid_ip(requestIP):
                print(f"Warning: Received request from disallowed IP: {requestIP}")
                continue  # Skip processing the request

            transaction_id, domain_name = parseUDPpacket(data)

            if transaction_id is None or domain_name is None:
                print("Error: Could not parse packet.")
                continue

            record = resolveName(domain_name)

            if record:
                sendResponse(requestIP, transaction_id, record)
            else:
                print(f"Error: Could not resolve {domain_name}")
                # Optionally, send an error response back to the client.

    except Exception as e:
        print(f"Error in UDPMessaging: {e}")
    finally:
        if 'sock' in locals():
            sock.close()


if __name__ == '__main__':
    UDP_IP = "127.0.0.1"  # Listen on localhost
    UDP_PORT = 5005

    UDPMessaging(UDP_IP, UDP_PORT)

