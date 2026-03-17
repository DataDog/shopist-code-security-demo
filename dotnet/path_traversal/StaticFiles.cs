using System.IO;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("[controller]")]
public class StaticFilesController : ControllerBase
{
    private const string StaticDir = "/var/www/static";

    // VULN 1: Directory.GetFiles with user-controlled directory - exposes arbitrary directory contents
    [HttpGet("browse")]
    public IActionResult BrowseDirectory(string dir = "")
    {
        string target = Path.Combine(StaticDir, dir);
        string[] entries = Directory.GetFiles(target);
        return Ok(entries);
    }

    // VULN 2: File.ReadAllBytes with string interpolation - user controls name and type
    [HttpGet("asset")]
    public IActionResult ServeAsset(string name, string type)
    {
        string filePath = $"{StaticDir}/{type}/{name}";
        byte[] content = System.IO.File.ReadAllBytes(filePath);
        return File(content, "application/octet-stream");
    }

    // VULN 3: File.Copy with user-controlled destination - write to arbitrary path
    [HttpPost("copy")]
    public IActionResult CopyTemplate(string template, string dest)
    {
        string src = Path.Combine(StaticDir, "templates", template);
        System.IO.File.Copy(src, dest, overwrite: true);
        return Ok("copied");
    }
}
