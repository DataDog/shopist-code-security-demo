using System.IO;
using System.IO.Compression;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("[controller]")]
public class FileUploadController : ControllerBase
{
    private const string UploadDir = "/var/www/uploads";

    // VULN 1: Save uploaded file to user-specified destination - arbitrary file write
    [HttpPost("upload")]
    public IActionResult UploadFile(IFormFile file, string destination)
    {
        string savePath = Path.Combine(UploadDir, destination);
        using var stream = new FileStream(savePath, FileMode.Create);
        file.CopyTo(stream);
        return Ok("uploaded");
    }

    // VULN 2: Zip extraction to user-controlled directory - zip slip vulnerability
    [HttpPost("extract")]
    public IActionResult ExtractArchive(IFormFile archive, string extractTo)
    {
        string archivePath = Path.Combine(UploadDir, archive.FileName);
        using (var stream = new FileStream(archivePath, FileMode.Create))
            archive.CopyTo(stream);

        // ZipFile.ExtractToDirectory does not validate entry paths against extractTo
        ZipFile.ExtractToDirectory(archivePath, extractTo, overwriteFiles: true);
        return Ok("extracted");
    }

    // VULN 3: Read file using user-controlled filename - path traversal on read
    [HttpGet("preview")]
    public IActionResult PreviewUpload(string user, string file)
    {
        string path = UploadDir + "/" + user + "/" + file;
        string content = System.IO.File.ReadAllText(path);
        return Ok(content);
    }
}
