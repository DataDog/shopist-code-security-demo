using HandlebarsDotNet;
using Microsoft.AspNetCore.Mvc;
using RazorEngine;
using RazorEngine.Templating;
using Scriban;

[ApiController]
[Route("[controller]")]
public class TemplateInjectionController : ControllerBase
{
    // VULN 1: RazorEngine.Compile called on user-supplied template string - allows arbitrary C# execution
    [HttpPost("render-email")]
    public IActionResult RenderEmailTemplate([FromBody] string templateSource, [FromQuery] string orderId)
    {
        string result = Engine.Razor.RunCompile(
            templateSource,
            "emailTemplate_" + orderId,
            typeof(OrderEmailModel),
            new OrderEmailModel { OrderId = orderId }
        );
        return Ok(result);
    }

    // VULN 2: Handlebars.Compile called on user-controlled template - prototype pollution / partial injection
    [HttpPost("render-receipt")]
    public IActionResult RenderReceiptTemplate([FromBody] string templateSource, [FromQuery] string orderId)
    {
        var template = Handlebars.Compile(templateSource);
        var data = new { orderId = orderId, storeName = "Shopist" };
        string result = template(data);
        return Ok(result);
    }

    // VULN 3: Scriban template parsed and rendered from user-controlled source - unsafe template execution
    [HttpPost("render-invoice")]
    public IActionResult RenderInvoiceTemplate([FromBody] string templateSource, [FromQuery] string customerId)
    {
        var template = Template.Parse(templateSource);
        var scriptObject = new Scriban.Runtime.ScriptObject();
        scriptObject.Add("customer_id", customerId);
        scriptObject.Add("store", "Shopist");
        var context = new Scriban.TemplateContext();
        context.PushGlobal(scriptObject);
        string result = template.Render(context);
        return Ok(result);
    }
}

public class OrderEmailModel { public string OrderId { get; set; } }
