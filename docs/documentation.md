Installation

 - scapy
    Globally: apt install python3-scapy
    In venv: python3 -m pip install scapy

Install venv:
cd ./backend/scan_scripts
sudo apt install python3.12-venv

Activate venv:
~/Kingmax/DevProjects/wifi-device-manager/backend/
source scan_scripts/.venv/bin/activate

Start venv:
sudo python3 -m venv .venv

!Set up virtual env interpreter
Run from project root (wifi-device-manager) if encounter import errors.


Create new WebApi

- dotnet new webapi (Creates a new WebApi project)
- dotnet build
- dotnet run

Running the backend with script:
dotnet build && dotnet run

If throws this error:
File "/usr/lib/python3.12/socket.py", line 233, in __init__ _socket.socket.__init__(self, family, type, proto, fileno) PermissionError: [Errno 1] Operation not permitted

Solution:
Run the backend with root permissions.
Or check if the script is running with venv interpreter.

Check the endpoint results:
http://localhost:5267/swagger
