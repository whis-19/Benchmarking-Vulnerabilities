import subprocess
import shlex

element = "some potentially dangerous string"  # Example: "'; rm -rf /'"

command = ["some_command", shlex.quote(element)]

try:
    result = subprocess.run(command, capture_output=True, text=True, check=True, shell=False)
    print("Command output:", result.stdout)
    print("Command error:", result.stderr)
except subprocess.CalledProcessError as e:
    print("Command failed:", e)
    print("Command output:", e.stdout)
    print("Command error:", e.stderr)
except FileNotFoundError:
    print("Command not found")

