parsed_url = urlparse(url)
    if parsed_url.scheme and parsed_url.scheme not in ['http', 'https']:  # Or just allow None
        logging.warning(f"Invalid URL scheme: {parsed_url.scheme}")
        return None
    hostname = parsed_url.hostname

