import socket
import scapy.all as scapy

def sniff_packets(interface):
    """Sniffs network packets on a given interface."""
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    """Processes a captured packet and prints its details."""
    if packet.haslayer(scapy.http.HTTPRequest):
        url = packet[scapy.http.HTTPRequest].Host.decode() + packet[scapy.http.HTTPRequest].Path.decode()
        print(f"[+] HTTP Request >> {url}")
        
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode()
            print(f"[+] Raw Data >> {load}")

def get_ip():
    """Gets the machine's IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

if __name__ == '__main__':
    interface = "wlan0"  # Replace with your wireless interface (e.g., wlan0, wlp3s0)
    try:
        print(f"Sniffing packets on {interface}...")
        sniff_packets(interface)
    except PermissionError:
        print("Error: You need root privileges to run this script.  Try running with sudo.")
    except Exception as e:
        print(f"An error occurred: {e}")

    # The most likely consequence is the interception of unencrypted data.
    # This includes HTTP traffic (credentials, session cookies, etc.).

    # This script demonstrates how an on-path attacker can capture and view
    # unencrypted HTTP traffic, showcasing the risks of using unsecured WiFi.