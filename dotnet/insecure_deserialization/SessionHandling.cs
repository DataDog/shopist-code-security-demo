using System;
using System.IO;
using System.Web;
using System.Web.Script.Serialization;
using System.Web.UI;
using System.Xml.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("[controller]")]
public class SessionHandlingController : ControllerBase
{
    // VULN 1: JavaScriptSerializer.Deserialize with user-controlled __type hint - gadget chain execution
    [HttpPost("restore-session")]
    public IActionResult RestoreSession([FromBody] string sessionJson)
    {
        var serializer = new JavaScriptSerializer();
        serializer.RegisterConverters(new[] { new SimpleTypeResolver() });
        var session = serializer.DeserializeObject(sessionJson);
        return Ok(session);
    }

    // VULN 2: XmlSerializer instantiated with user-controlled type name - type confusion
    [HttpPost("load-profile")]
    public IActionResult LoadUserProfile([FromBody] string profileXml, [FromQuery] string typeName)
    {
        var targetType = Type.GetType(typeName);
        var xmlSerializer = new XmlSerializer(targetType);
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(profileXml);
        using var stream = new MemoryStream(xmlBytes);
        var profile = xmlSerializer.Deserialize(stream);
        return Ok(profile);
    }

    // VULN 3: LosFormatter.Deserialize on base64-encoded value from request parameter - ViewState-style attack
    [HttpGet("load-state")]
    public IActionResult LoadViewState([FromQuery] string state)
    {
        byte[] stateBytes = Convert.FromBase64String(state);
        using var stream = new MemoryStream(stateBytes);
        var formatter = new LosFormatter();
        var viewState = formatter.Deserialize(stream);
        return Ok(viewState);
    }
}

public class SimpleTypeResolver : JavaScriptTypeResolver
{
    public override Type ResolveType(string id) => Type.GetType(id);
    public override string ResolveTypeId(Type type) => type.FullName;
}
