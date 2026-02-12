import os

def process_file(filename):
    # Potentially vulnerable if filename is attacker-controlled
    os.system(f"process_tool {filename}")

user_input = input("Enter a number: ")
safe_result = safe_add(user_input)

if safe_result is not None:
    # Attacker provides input that results in this filename:
    # data_10; rm -rf /.txt
    filename = f"data_{safe_result}.txt"  # Constructing a filename
    process_file(filename)

