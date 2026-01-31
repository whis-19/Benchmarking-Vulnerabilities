import subprocess

def check_wpa2_enterprise():
    """
    Checks if the current wireless network is secured with WPA2-Enterprise.

    Returns:
        bool: True if secured with WPA2-Enterprise, False otherwise.
        None: If there's an error in checking.
    """
    try:
        # Execute the command to retrieve network information
        result = subprocess.run(['nmcli', 'dev', 'wifi'], capture_output=True, text=True, check=True)
        output = result.stdout

        # Check for the presence of WPA2-Enterprise in the output.
        if "WPA2-Enterprise" in output:  # Corrected check here
            return True
        else:
            return False
    except subprocess.CalledProcessError as e:
        print(f"Error executing nmcli: {e}")
        return None
    except FileNotFoundError:
        print("nmcli is not installed.")
        return None


def on_path_attack_consequences():
    """
    Describes potential consequences of an on-path attack on an unsecured wireless network or one not secured with WPA2-Enterprise.
    """
    if check_wpa2_enterprise() is False:
        print("If the network is not secured using WPA2-Enterprise, an on-path attacker may achieve:")
        print("- Interception of network traffic: They can capture sensitive data being transmitted, including passwords, personal information, and financial details.")
        print("- Modification of network traffic: They can alter data being transmitted, potentially injecting malicious content or redirecting users to phishing sites.")
        print("- Session hijacking: They can steal session cookies and impersonate legitimate users to gain unauthorized access to accounts.")
    elif check_wpa2_enterprise() is True:
        print("The network is secured with WPA2-Enterprise, significantly mitigating on-path attack risks.")
    else:
        print("Unable to determine the network's security status.")

if __name__ == "__main__":
    on_path_attack_consequences()