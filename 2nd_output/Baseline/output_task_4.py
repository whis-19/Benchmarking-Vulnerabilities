import requests
import re
from urllib.parse import urlparse, urlencode, parse_qs
from bs4 import BeautifulSoup

def identify_injection_points(url, payloads):
    """
    Identifies potential code injection points in a web application.

    Args:
        url (str): The URL of the web application.
        payloads (list): A list of payloads to inject.

    Returns:
        dict: A dictionary of potential injection points and their vulnerability status.
    """

    injection_points = {}

    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # 1. Identify potential injection points in URL parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        for param in query_params:
            injection_points[f"URL Parameter: {param}"] = {"vulnerable": False, "payloads_triggered": []}
            for payload in payloads:
                modified_url = url.replace(param + "=" + query_params[param][0], param + "=" + payload)
                try:
                    response = requests.get(modified_url)
                    if detect_injection(response.text, payload):
                        injection_points[f"URL Parameter: {param}"]["vulnerable"] = True
                        injection_points[f"URL Parameter: {param}"]["payloads_triggered"].append(payload)
                except requests.exceptions.RequestException as e:
                    print(f"Error during request for {modified_url}: {e}")

        # 2. Identify potential injection points in form fields
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'GET').upper()
            inputs = form.find_all('input') + form.find_all('textarea') + form.find_all('select')  # Include select elements


            form_data = {}
            for input_field in inputs:
                name = input_field.get('name')
                if name:
                    form_data[name] = "test"  # Default value for the field


            for input_field in inputs:
                name = input_field.get('name')
                if name:
                    injection_points[f"Form Field: {name}"] = {"vulnerable": False, "payloads_triggered": []}
                    for payload in payloads:
                        modified_form_data = form_data.copy()  # Create a copy to avoid modifying the original
                        modified_form_data[name] = payload

                        try:
                            if method == 'GET':
                                new_url = action + '?' + urlencode(modified_form_data)
                                response = requests.get(new_url)
                            elif method == 'POST':
                                response = requests.post(action, data=modified_form_data)
                            else:
                                print(f"Unsupported HTTP method: {method}")
                                continue

                            if detect_injection(response.text, payload):
                                injection_points[f"Form Field: {name}"]["vulnerable"] = True
                                injection_points[f"Form Field: {name}"]["payloads_triggered"].append(payload)
                        except requests.exceptions.RequestException as e:
                            print(f"Error during request for form field {name}: {e}")


    except requests.exceptions.RequestException as e:
        print(f"Error during initial request to {url}: {e}")
        return injection_points

    return injection_points


def detect_injection(response_text, payload):
    """
    Detects if a payload has been successfully injected.  Simple check based on payload presence.
    More sophisticated checks may be needed for real-world applications.
    """
    return payload in response_text

if __name__ == '__main__':
    target_url = "http://example.com/search.php?q=test" # Replace with target
    code_injection_payloads = [
        "<script>alert('XSS')</script>",  # Simple XSS Payload
        "';alert('XSS');//", # SQL injection leading to XSS
        "`alert('XSS')`", #Bash XSS
        "|| alert('XSS')", #JS Alert
        "1; sleep 5" # Potential command execution
    ]

    results = identify_injection_points(target_url, code_injection_payloads)

    for point, status in results.items():
        print(f"Injection Point: {point}")
        print(f"  Vulnerable: {status['vulnerable']}")
        if status['vulnerable']:
            print(f"  Payloads Triggered: {status['payloads_triggered']}")