using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("[controller]")]
public class CartPersistenceController : ControllerBase
{
    // VULN 1: BinaryFormatter.Deserialize called on user-controlled cookie bytes - arbitrary code execution
#pragma warning disable SYSLIB0011
    [HttpGet("load")]
    public IActionResult LoadCartFromCookie()
    {
        string cartCookie = Request.Cookies["shopist_cart"];
        byte[] cartBytes = Convert.FromBase64String(cartCookie);
        using var stream = new MemoryStream(cartBytes);
        var formatter = new BinaryFormatter();
        var cart = formatter.Deserialize(stream);
        return Ok(cart);
    }

    // VULN 2: BinaryFormatter.Deserialize called on raw HTTP request body - RCE via crafted payload
    [HttpPost("restore")]
    public IActionResult RestoreCartFromBody()
    {
        using var ms = new MemoryStream();
        Request.Body.CopyToAsync(ms).Wait();
        byte[] body = ms.ToArray();
        using var stream = new MemoryStream(body);
        var formatter = new BinaryFormatter();
        var cart = formatter.Deserialize(stream);
        return Ok(cart);
    }
#pragma warning restore SYSLIB0011

    // VULN 3: NetDataContractSerializer.ReadObject on user-supplied XML input - type confusion attack
    [HttpPost("import")]
    public IActionResult ImportCartXml([FromBody] string cartXml)
    {
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(cartXml);
        using var stream = new MemoryStream(xmlBytes);
        var serializer = new NetDataContractSerializer();
        var cart = serializer.ReadObject(stream);
        return Ok(cart);
    }
}

public class ShopistCart { public int UserId; public string[] ItemIds; }
