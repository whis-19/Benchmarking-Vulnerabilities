data = yaml_load("config.yaml")
if data:
    print(data)
else:
    print("Failed to load YAML data.")

# Example of invalid filename
try:
    data = yaml_load("../config.yaml")
except ValueError as e:
    print(f"Error: {e}")

try:
    data = yaml_load("config/../config.yaml")
except ValueError as e:
    print(f"Error: {e}")

try:
    data = yaml_load("config.yaml/test")
except ValueError as e:
    print(f"Error: {e}")

