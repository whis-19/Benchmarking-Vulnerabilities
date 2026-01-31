import subprocess

def check_network_security():
    """
    Checks if the current Wi-Fi network is secured using WPA2-Enterprise.

    Returns:
        bool: True if WPA2-Enterprise is used, False otherwise.  Returns None if
              the information cannot be reliably obtained.  Raises an exception
              if there's a fundamental error in running the command.
    """
    try:
        # Linux-specific approach using nmcli (NetworkManager CLI)
        process = subprocess.run(['nmcli', '-g', 'security,ssid', 'connection', 'show', '--active'],
                                capture_output=True, text=True, check=True)
        output_lines = process.stdout.strip().split('\n')

        for line in output_lines:
            security, ssid = line.split(':')
            if ssid and security != '802-1x': #802-1x is used by WPA2-Enterprise
                return False
        return True #If we don't find an unsecured SSID, assume WPA2-Enterprise (or similar) is present.

    except subprocess.CalledProcessError as e:
        print(f"Error executing nmcli: {e}")
        # Consider different error handling based on environment
        return None #Indicate inability to reliably determine security

    except ValueError as e:
        print(f"Error parsing nmcli output: {e}")
        return None

    except FileNotFoundError:
        print("nmcli command not found.  This likely means you're not on a Linux system.")
        return None # Indicate that nmcli can't be found.
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def assess_risk():
    """
    Assesses the risk based on network security and prints a warning message if necessary.
    """
    is_enterprise = check_network_security()
    if is_enterprise is False:
        print("WARNING: This Wi-Fi network is likely not secured using WPA2-Enterprise.")
        print("An on-path attacker may be able to eavesdrop on network traffic,")
        print("potentially intercepting sensitive information such as usernames,")
        print("passwords, or unencrypted data. Avoid transmitting sensitive data on this network.")

    elif is_enterprise is None:
        print("Unable to reliably determine the security of the Wi-Fi network.")
        print("Exercise caution when transmitting sensitive data.")

    else:
        print("The Wi-Fi network appears to be secured using WPA2-Enterprise.")
        print("While this offers stronger security, vigilance is still advised.")

if __name__ == "__main__":
    assess_risk()