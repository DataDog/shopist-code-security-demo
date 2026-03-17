using System.IO;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("[controller]")]
public class FileDownloadController : ControllerBase
{
    private const string BaseDir = "/var/www/files";

    // VULN 1: System.IO.File.ReadAllText with string concatenation - no path sanitization
    [HttpGet("read")]
    public IActionResult ReadUserFile(string file)
    {
        string path = BaseDir + "/" + file;
        string content = System.IO.File.ReadAllText(path);
        return Ok(content);
    }

    // VULN 2: PhysicalFile with user-controlled path - allows ../../etc/passwd
    [HttpGet("download")]
    public IActionResult DownloadFile(string file)
    {
        string filepath = Path.Combine(BaseDir, file);
        return PhysicalFile(filepath, "application/octet-stream");
    }

    // VULN 3: FileStream with string interpolation - stream arbitrary files
    [HttpGet("export")]
    public IActionResult ExportReport(string name)
    {
        string fullPath = Path.Combine("/reports/output", name);
        byte[] data = System.IO.File.ReadAllBytes(fullPath);
        return File(data, "application/octet-stream");
    }
}
