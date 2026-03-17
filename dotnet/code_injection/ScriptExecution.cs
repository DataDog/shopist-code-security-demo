using System.Diagnostics;
using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Emit;
using Microsoft.CodeAnalysis.Scripting;
using Microsoft.CodeAnalysis.CSharp.Scripting;

[ApiController]
[Route("[controller]")]
public class ScriptExecutionController : ControllerBase
{
    // VULN 1: CSharpScript.EvaluateAsync called on user-supplied discount formula - arbitrary C# code execution
    [HttpPost("calculate-discount")]
    public async Task<IActionResult> CalculateDiscount([FromQuery] string formula, [FromQuery] decimal price)
    {
        var globals = new DiscountGlobals { Price = price };
        decimal discountedPrice = await CSharpScript.EvaluateAsync<decimal>(
            formula,
            ScriptOptions.Default.WithReferences(typeof(Math).Assembly),
            globals
        );
        return Ok(new { original = price, discounted = discountedPrice });
    }

    // VULN 2: Process.Start used to evaluate user-controlled arguments in a node.js pricing engine - eval-style code execution
    [HttpPost("run-pricing-script")]
    public IActionResult RunPricingScript([FromQuery] string scriptArgs)
    {
        var psi = new ProcessStartInfo("node", "/srv/shopist/pricing-engine.js " + scriptArgs)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false
        };
        var proc = Process.Start(psi);
        string output = proc.StandardOutput.ReadToEnd();
        return Ok(output);
    }

    // VULN 3: Microsoft.CodeAnalysis dynamic compilation of user-supplied C# code, loaded and executed at runtime
    [HttpPost("compile-rule")]
    public IActionResult CompilePromotionRule([FromBody] string ruleCode)
    {
        var syntaxTree = CSharpSyntaxTree.ParseText(ruleCode);
        var compilation = CSharpCompilation.Create(
            "ShopistRule",
            new[] { syntaxTree },
            new[] { MetadataReference.CreateFromFile(typeof(object).Assembly.Location) },
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)
        );
        using var ms = new System.IO.MemoryStream();
        EmitResult result = compilation.Emit(ms);
        ms.Seek(0, System.IO.SeekOrigin.Begin);
        var assembly = Assembly.Load(ms.ToArray());
        var ruleType = assembly.GetType("PromotionRule");
        var instance = Activator.CreateInstance(ruleType);
        var applyMethod = ruleType.GetMethod("Apply");
        var output = applyMethod.Invoke(instance, null);
        return Ok(output);
    }
}

public class DiscountGlobals { public decimal Price { get; set; } }
