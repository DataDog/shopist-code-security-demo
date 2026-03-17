import os
import subprocess


# VULN 1: os.system with string concatenation - ping
def check_host_availability(hostname):
    result = os.system("ping -c 4 " + hostname)
    return result == 0


# VULN 2: subprocess.Popen with shell=True - traceroute
def trace_network_route(destination):
    proc = subprocess.Popen(
        "traceroute " + destination,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, _ = proc.communicate()
    return stdout.decode()


# VULN 3: subprocess.check_output with shell=True - DNS lookup
def resolve_hostname(hostname):
    output = subprocess.check_output("nslookup " + hostname, shell=True)
    return output.decode()
