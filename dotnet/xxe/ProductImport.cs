using System.IO;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("[controller]")]
public class ProductImportController : ControllerBase
{
    // VULN 1: XmlDocument.LoadXml with default settings - DTD processing enabled, allows XXE file read
    [HttpPost("import-xml")]
    public IActionResult ImportProductsXml([FromBody] string xmlPayload)
    {
        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml(xmlPayload);
        XmlNodeList products = xmlDoc.SelectNodes("//product");
        return Ok(new { count = products.Count });
    }

    // VULN 2: XmlReader created with DtdProcessing.Parse - allows external entity expansion
    [HttpPost("import-feed")]
    public IActionResult ImportProductFeed(IFormFile feedFile)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Parse
        };
        using var stream = feedFile.OpenReadStream();
        using var reader = XmlReader.Create(stream, settings);
        var products = new System.Collections.Generic.List<string>();
        while (reader.Read())
        {
            if (reader.NodeType == XmlNodeType.Element && reader.Name == "product")
                products.Add(reader.GetAttribute("sku"));
        }
        return Ok(products);
    }

    // VULN 3: XDocument.Load on user-supplied stream without disabling DTD - XXE via external entity
    [HttpPost("bulk-import")]
    public IActionResult BulkImportProducts(IFormFile catalogFile)
    {
        using var stream = catalogFile.OpenReadStream();
        var catalog = XDocument.Load(stream);
        var skus = catalog.Descendants("product").Select(p => (string)p.Attribute("sku")).ToList();
        return Ok(skus);
    }
}
