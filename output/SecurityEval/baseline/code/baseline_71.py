import socket
import struct
import random

def parseUDPpacket(data):
    """
    Parses a UDP packet containing a DNS query.  This is a simplified example
    and may need to be expanded for full DNS functionality.

    Args:
        data: The raw bytes received in the UDP packet.

    Returns:
        A tuple containing the query name (string) and the query type (integer),
        or None if parsing fails.  Returns the transaction ID as well.
    """
    try:
        # Basic sanity check:  Packet must be at least 12 bytes (DNS header)
        if len(data) < 12:
            print("Error: Packet too short to be a valid DNS query.")
            return None, None, None

        # Extract the transaction ID (first 2 bytes)
        transaction_id = data[:2]

        # Extract flags (next 2 bytes) - not used in this simplified example
        flags = data[2:4]

        # Extract number of questions (next 2 bytes)
        num_questions = struct.unpack("!H", data[4:6])[0]

        # We're only handling single-question queries for simplicity
        if num_questions != 1:
            print("Error: Only single-question queries are supported.")
            return None, None, None

        # Skip the answer, authority, and additional records counts (6 bytes)
        offset = 12

        # Parse the query name (variable length)
        query_name = ""
        while True:
            length = data[offset]
            offset += 1
            if length == 0:
                break
            query_name += data[offset:offset + length].decode("utf-8") + "."
            offset += length

        query_name = query_name[:-1]  # Remove trailing dot

        # Extract the query type (2 bytes)
        query_type = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        # Extract the query class (2 bytes) - typically 1 for IN (Internet)
        query_class = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        return query_name, query_type, transaction_id

    except Exception as e:
        print(f"Error parsing UDP packet: {e}")
        return None, None, None


def resolveName(nameToResolve):
    """
    Simulates DNS resolution.  In a real DNS server, this would involve
    querying other DNS servers or consulting a local database.

    Args:
        nameToResolve: The domain name to resolve (string).

    Returns:
        A dictionary representing the DNS record, or None if resolution fails.
        For example:
        {
            "name": "example.com",
            "type": 1,  # A record
            "class": 1,  # IN (Internet)
            "ttl": 300,  # Time to live (seconds)
            "data": "192.0.2.1"  # IP address
        }
    """
    # Simple example:  Hardcoded resolution for example.com
    if nameToResolve == "example.com":
        return {
            "name": "example.com",
            "type": 1,  # A record
            "class": 1,  # IN (Internet)
            "ttl": 300,
            "data": "192.0.2.1"
        }
    elif nameToResolve == "google.com":
        return {
            "name": "google.com",
            "type": 1,  # A record
            "class": 1,  # IN (Internet)
            "ttl": 300,
            "data": "142.250.185.142"
        }
    else:
        print(f"Name resolution failed for: {nameToResolve}")
        return None


def sendResponse(requestIP, record, transaction_id):
    """
    Constructs and sends a DNS response packet to the requesting IP address.

    Args:
        requestIP: The IP address to send the response to (string).
        record: A dictionary representing the DNS record to send.
        transaction_id: The transaction ID from the original request.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Construct the DNS response packet
        response = b""

        # Transaction ID (copied from request)
        response += transaction_id

        # Flags:  Response, Authoritative Answer, Recursion Available
        flags = 0x8180  # Standard query response, authoritative, recursion available
        response += struct.pack("!H", flags)

        # Number of questions (1)
        response += struct.pack("!H", 1)

        # Number of answer records (1 if record is found, 0 otherwise)
        if record:
            response += struct.pack("!H", 1)
        else:
            response += struct.pack("!H", 0)

        # Number of authority records (0)
        response += struct.pack("!H", 0)

        # Number of additional records (0)
        response += struct.pack("!H", 0)

        # Encode the query name (same as in the request)
        name = record["name"] if record else ""
        qname = b""
        for part in name.split("."):
            qname += struct.pack("B", len(part))
            qname += part.encode("utf-8")
        qname += b"\x00"  # Null terminator

        response += qname

        # Query type (A record = 1)
        response += struct.pack("!H", 1)

        # Query class (IN = 1)
        response += struct.pack("!H", 1)

        # Answer record (if a record was found)
        if record:
            # Name (pointer to query name)
            response += b"\xc0\x0c"  # Pointer to offset 12 (start of query name)

            # Type (A record = 1)
            response += struct.pack("!H", record["type"])

            # Class (IN = 1)
            response += struct.pack("!H", record["class"])

            # TTL (Time to Live)
            response += struct.pack("!I", record["ttl"])

            # Data length (4 bytes for IPv4 address)
            response += struct.pack("!H", 4)

            # IP address
            ip_address = record["data"]
            response += socket.inet_aton(ip_address)

        # Send the response
        sock.sendto(response, (requestIP[0], requestIP[1]))  # requestIP is a tuple (ip, port)
        print(f"Response sent to {requestIP[0]}:{requestIP[1]}")
        sock.close()

    except Exception as e:
        print(f"Error sending response: {e}")


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
            print(f"Received message from {addr}")

            query_name, query_type, transaction_id = parseUDPpacket(data)

            if query_name and query_type and transaction_id:
                record = resolveName(query_name)
                sendResponse(addr, record, transaction_id)
            else:
                print("Failed to parse UDP packet.  Ignoring.")

    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if 'sock' in locals():
            sock.close()
            print("Socket closed.")


if __name__ == "__main__":
    UDP_IP = "127.0.0.1"  # Listen on localhost
    UDP_PORT = 5353  # Use a non-standard port for testing (avoid needing root)
    UDPMessaging(UDP_IP, UDP_PORT)

