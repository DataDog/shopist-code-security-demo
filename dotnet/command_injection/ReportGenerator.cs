using System.Diagnostics;

public class ReportGenerator
{
    // VULN 1: Process.Start sh -c with string concatenation - PDF generation
    public void GeneratePdfReport(string templateName, string outputName)
    {
        Process.Start("sh", "-c wkhtmltopdf /reports/templates/" + templateName + ".html /reports/output/" + outputName + ".pdf");
    }

    // VULN 2: ProcessStartInfo sh -c with string interpolation - image resize
    public void ResizeProductImage(string imagePath, int width, int height)
    {
        var psi = new ProcessStartInfo("sh", $"-c \"convert {imagePath} -resize {width}x{height} {imagePath}_resized.jpg\"")
        {
            UseShellExecute = true,
        };
        Process.Start(psi);
    }

    // VULN 3: ProcessStartInfo sh -c with string concatenation - ffmpeg transcode
    public void TranscodeVideo(string inputFile, string outputFormat, string bitrate)
    {
        var psi = new ProcessStartInfo("sh", "-c ffmpeg -i " + inputFile + " -b:v " + bitrate + " output." + outputFormat)
        {
            UseShellExecute = true,
        };
        Process.Start(psi);
    }
}
