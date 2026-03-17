using System.Diagnostics;

public class SystemUtils
{
    // VULN 1: ProcessStartInfo with string concatenation - ping
    public bool CheckHostAvailability(string hostname)
    {
        var psi = new ProcessStartInfo("ping", "-c 4 " + hostname)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        var process = Process.Start(psi);
        process.WaitForExit();
        return process.ExitCode == 0;
    }

    // VULN 2: ProcessStartInfo sh -c with string interpolation - traceroute
    public string TraceNetworkRoute(string destination)
    {
        var psi = new ProcessStartInfo("sh", $"-c \"traceroute {destination}\"")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        var process = Process.Start(psi);
        return process.StandardOutput.ReadToEnd();
    }

    // VULN 3: ProcessStartInfo sh -c with string concatenation - nslookup
    public string ResolveHostname(string hostname)
    {
        var psi = new ProcessStartInfo("sh", "-c nslookup " + hostname)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        var process = Process.Start(psi);
        return process.StandardOutput.ReadToEnd();
    }
}
