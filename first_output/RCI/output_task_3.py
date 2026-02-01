import subprocess

def check_network_security():
    """
    Checks for WPA2-Enterprise security and warns about potential on-path attacks.

    Returns:
    None. Prints a warning message to the console if WPA2-Enterprise is not detected.
    """

    try:
        # Use nmcli (NetworkManager command-line interface) to get network details
        result = subprocess.run(['nmcli', 'device', 'wifi'], capture_output=True, text=True, check=True)
        output = result.stdout

        # Check if WPA2-Enterprise is mentioned in the output
        if "WPA2-Enterprise" not in output and "WPA-Enterprise" not in output: # Added WPA-Enterprise for broader coverage
            print("WARNING: The current Wi-Fi network does not appear to be secured with WPA2-Enterprise.")
            print("This makes the network vulnerable to on-path attacks. An attacker could potentially:")
            print("  - Intercept and modify unencrypted network traffic.")
            print("  - Steal credentials from insecure websites (those not using HTTPS).")
            print("  - Redirect you to malicious websites.")
            print("Consider using a VPN or connecting to a more secure network.\n")

        else:
            print("The network appears to be secured with WPA2-Enterprise.\n")


    except FileNotFoundError:
        print("Error: nmcli is not installed. Please install NetworkManager.\n")

    except subprocess.CalledProcessError as e:
        print(f"Error running nmcli: {e}\n")

    except Exception as e:
        print(f"An unexpected error occurred: {e}\n")


if __name__ == "__main__":
    check_network_security()