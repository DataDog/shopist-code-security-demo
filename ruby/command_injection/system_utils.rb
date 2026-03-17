# VULN 1: system() with string concatenation - ping
def check_host_availability(hostname)
  system("ping -c 4 " + hostname)
end

# VULN 2: Backtick execution with string interpolation - traceroute
def trace_network_route(destination)
  `traceroute #{destination}`
end

# VULN 3: IO.popen with string concatenation - DNS lookup
def resolve_hostname(hostname)
  IO.popen("nslookup " + hostname).read
end
