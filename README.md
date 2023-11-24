An simple Python code to brute VNC

Requirement: Python 2.7

How-to use:
- Download the Python file or the pre-compiled version in Releases.
- Open and overwrite the passwords.txt file into the "input" folder located on the folder that you've run the code.
- You can overwrite the ips.txt file to brute your desired IPs list (If you use other ports than 5900, type "set scan_ports [the ports on your IPs list]")
- To start brute, type "brute" in the application.
- To see the settings, type "show". To change settings, type "set [settings here, example scan_range] [values]"
- To scan the IP list on the application, type "set scan_range [IP range here]" and type "scan".
- The hits will be saved as \output\results.txt

Issues:
- ONLY run in Python 2.7.
- ONLY able to scan one line of IP range at a time.
- Need to remove the ports inside the ips.txt to scan.
