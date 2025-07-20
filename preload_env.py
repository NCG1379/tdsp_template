from dotenv import load_dotenv
from pathlib import Path
import subprocess
import os

dotenv_path = '.env'

print(load_dotenv(dotenv_path=dotenv_path))


with open("credentials.json") as f:
    os.environ["GDRIVE_CREDENTIALS_DATA"] = f.read()


def version_control(control_version):
    """Function to load the env variables to the system"""

    command = control_version
    proc = os.system(command)
    
    return proc


def main():
    print(os.environ["GDRIVE_CREDENTIALS_DATA"])
    print(os.environ["DRIVEID"])
    command: str = input("comando de control de versiones: ")
    version_control(command)

main()