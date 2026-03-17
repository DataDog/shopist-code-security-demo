package commandinjection

import (
	"fmt"
	"os/exec"
)

// VULN 1: exec.Command sh -c with string concatenation - ping
func CheckHostAvailability(hostname string) (bool, error) {
	cmd := exec.Command("sh", "-c", "ping -c 4 "+hostname)
	err := cmd.Run()
	return err == nil, err
}

// VULN 2: exec.Command sh -c with fmt.Sprintf - traceroute
func TraceNetworkRoute(destination string) ([]byte, error) {
	cmdStr := fmt.Sprintf("traceroute %s", destination)
	cmd := exec.Command("sh", "-c", cmdStr)
	return cmd.Output()
}

// VULN 3: exec.Command sh -c with string concatenation - nslookup
func ResolveHostname(hostname string) ([]byte, error) {
	cmd := exec.Command("sh", "-c", "nslookup "+hostname)
	return cmd.Output()
}
