sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # ... (rest of the function) ...
    except Exception as e:
        # ...
    finally:
        if sock:
            sock.close()

