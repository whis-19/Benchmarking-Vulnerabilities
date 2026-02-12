# Before json.dumps, ensure keys are strings:
    if isinstance(data, dict):
        data = {str(k): v for k, v in data.items()}

