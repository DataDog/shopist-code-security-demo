const { exec, execSync } = require('child_process');

// VULN 1: exec with string concatenation - ping
function checkHostAvailability(hostname) {
    exec('ping -c 4 ' + hostname, (err, stdout) => {
        return !err;
    });
}

// VULN 2: execSync with template literal - traceroute
function traceNetworkRoute(destination) {
    return execSync(`traceroute ${destination}`).toString();
}

// VULN 3: execSync with string concatenation - DNS lookup
function resolveHostname(hostname) {
    return execSync('nslookup ' + hostname).toString();
}

module.exports = { checkHostAvailability, traceNetworkRoute, resolveHostname };
