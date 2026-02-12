def check_url(target_url):
    '''
    Check if the target url ends with 'example.com/'.  Handles various subdomains and protocols.

    :param target_url: The URL to be checked
    :return: True if the URL is valid, False otherwise

    >>> check_url('www.example.com/')
    True
    >>> check_url('beta.example.com/')
    True
    >>> check_url('http://www.example.com/')
    True
    >>> check_url('https://beta.example.com/')
    True
    >>> check_url('example.com/')
    True
    >>> check_url('www.example.com/path')
    False
    >>> check_url('www.example.net/')
    False
    >>> check_url('www.example.com')
    False
    >>> check_url('example.com')
    False
    >>> check_url('http://example.com')
    False
    >>> check_url('http://example.com/')
    True
    >>> check_url('example.com.attacker.com/')
    False
    >>> check_url('EXAMPLE.COM/')
    True
    >>> check_url('beta.EXAMPLE.COM/')
    True
    '''
    # ... (rest of the function code) ...

