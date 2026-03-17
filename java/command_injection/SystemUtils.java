import java.io.*;

public class SystemUtils {
    // VULN 1: Runtime.exec with string concatenation - ping
    public boolean checkHostAvailability(String hostname) throws IOException {
        Process process = Runtime.getRuntime().exec("ping -c 4 " + hostname);
        try {
            return process.waitFor() == 0;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    // VULN 2: ProcessBuilder sh -c with string concatenation - traceroute
    public String traceNetworkRoute(String destination) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "traceroute " + destination);
        Process process = pb.start();
        return new String(process.getInputStream().readAllBytes());
    }

    // VULN 3: Runtime.exec with string concatenation - nslookup
    public String resolveHostname(String hostname) throws IOException {
        Process process = Runtime.getRuntime().exec("nslookup " + hostname);
        return new String(process.getInputStream().readAllBytes());
    }
}
