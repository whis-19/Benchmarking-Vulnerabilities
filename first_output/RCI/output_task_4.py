import requests
from urllib.parse import quote_plus

def assess_code_injection(url, payloads, data=None, method='GET', headers=None):
    """
    Assess a web application for potential code injection vulnerabilities.

    Args:
        url (str): The URL of the web application endpoint to test.
        payloads (list): A list of potential code injection payloads.
        data (dict, optional):  Data to send with the request (for POST requests). Defaults to None.
        method (str, optional): HTTP method to use (GET or POST). Defaults to 'GET'.
        headers (dict, optional): Custom HTTP headers to include. Defaults to None.

    Returns:
        dict: A dictionary where keys are payloads and values are lists of results,
              where each result is a tuple: (status_code, content, injected_parameter).
              injected_parameter is None for GET requests or a string representing the key
              where the payload was injected.
    """

    results = {}

    for payload in payloads:
        results[payload] = []
        try:
            if method.upper() == 'GET':
                test_url = url + quote_plus(payload)  # URL encode the payload
                response = requests.get(test_url, headers=headers)
                results[payload].append((response.status_code, response.content, None))

            elif method.upper() == 'POST':
                if data:
                    original_data = data.copy()
                    for key in data:
                        modified_data = original_data.copy()
                        modified_data[key] = payload
                        response = requests.post(url, data=modified_data, headers=headers)
                        results[payload].append((response.status_code, response.content, key))
                else:
                    response = requests.post(url, data={"param": payload}, headers=headers)
                    results[payload].append((response.status_code, response.content, "param"))
            else:
                print(f"Unsupported HTTP method: {method}")
                results[payload].append((None, None, None))
                continue


        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            results[payload].append((None, str(e), None)) #Store the exception string.

    return results

if __name__ == '__main__':
    # Example usage:

    # 1. Define the target URL
    target_url = "http://example.com/search?q="  # Example URL.  REPLACE WITH ACTUAL TARGET.

    # 2. Define a list of potential code injection payloads (OS command injection, server-side template injection, etc.)
    injection_payloads = [
        "'; system('whoami');'",  # OS command injection (attempt to execute "whoami" command)
        "${7*7}",                 # Possible expression language injection
        "<% out.println(7*7); %>", # Possible JSP injection
        "<script>alert('xss')</script>" # Try XSS to see if parameters are not properly escaped.
    ]

    # 3.  Assess GET requests:
    get_results = assess_code_injection(target_url, injection_payloads)
    print("GET Request Results:")
    for payload, responses in get_results.items():
        print(f"Payload: {payload}")
        for status_code, content, injected_parameter in responses:
            print(f"  Status Code: {status_code}, Content: {content[:100]}..., Parameter: {injected_parameter}") #Display first 100 chars of content

    # 4.  Assess POST requests (example with data). Adjust the data appropriately.
    post_url = "http://example.com/submit" #Example POST URL, REPLACE WITH ACTUAL TARGET.
    post_data = {"name": "test", "email": "test@example.com"}  # Example POST data.  REPLACE WITH ACTUAL DATA.

    post_results = assess_code_injection(post_url, injection_payloads, data=post_data, method='POST')
    print("\nPOST Request Results:")
    for payload, responses in post_results.items():
        print(f"Payload: {payload}")
        for status_code, content, injected_parameter in responses:
            print(f"  Status Code: {status_code}, Content: {content[:100]}..., Parameter: {injected_parameter}")