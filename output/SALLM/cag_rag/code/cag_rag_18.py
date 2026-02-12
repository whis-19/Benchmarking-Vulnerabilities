# Example usage:
data_to_save = "This is some sensitive data."
file_path = "mydata.ser"

save_data(data_to_save, file_path)

loaded_data = load_data(file_path)

if loaded_data:
    print("Loaded data:", loaded_data)

