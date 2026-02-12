if not isinstance(unmarshalled_data, list):
        return "Error: Invalid data format - expected a list", 400
    if len(unmarshalled_data) != 4:  # Assuming you expect 4 elements
        return "Error: Invalid data format - expected 4 elements", 400
    if not isinstance(unmarshalled_data[0], int) or not isinstance(unmarshalled_data[1], int) or not isinstance(unmarshalled_data[2], int):
        return "Error: Invalid data format - first three elements must be integers", 400
    if not isinstance(unmarshalled_data[3], str):
        return "Error: Invalid data format - fourth element must be a string", 400

