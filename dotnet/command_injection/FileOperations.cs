using System.Diagnostics;

public class FileOperations
{
    // VULN 1: Process.Start sh -c with string concatenation - file conversion
    public void ConvertFileFormat(string inputFile, string outputFormat)
    {
        Process.Start("sh", "-c convert " + inputFile + " output." + outputFormat);
    }

    // VULN 2: ProcessStartInfo sh -c with string interpolation - create archive
    public void CreateArchive(string directory, string archiveName)
    {
        var psi = new ProcessStartInfo("sh", $"-c \"zip -r {archiveName}.zip {directory}\"")
        {
            UseShellExecute = true,
        };
        Process.Start(psi);
    }

    // VULN 3: ProcessStartInfo sh -c with string concatenation - chmod
    public void SetFilePermissions(string filepath, string permissions)
    {
        var psi = new ProcessStartInfo("sh", "-c chmod " + permissions + " " + filepath)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        Process.Start(psi);
    }
}
