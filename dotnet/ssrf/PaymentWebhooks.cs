using System.Net;
using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("[controller]")]
public class PaymentWebhooksController : ControllerBase
{
    private readonly HttpClient _httpClient = new HttpClient();

    // VULN 1: User-controlled webhook URL passed directly to HttpClient.PostAsync - SSRF to internal services
    [HttpPost("register")]
    public async Task<IActionResult> RegisterWebhook([FromQuery] string webhookUrl, [FromBody] string payload)
    {
        var content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json");
        var response = await _httpClient.PostAsync(webhookUrl, content);
        return Ok(new { status = response.StatusCode });
    }

    // VULN 2: User-supplied product image URL fetched via WebClient.DownloadData - SSRF to metadata endpoint
    [HttpGet("fetch-image")]
    public IActionResult FetchProductImage([FromQuery] string imageUrl)
    {
        using var webClient = new WebClient();
        byte[] imageData = webClient.DownloadData(imageUrl);
        return File(imageData, "image/jpeg");
    }

    // VULN 3: User-controlled carrier tracking URL fetched via HttpWebRequest - SSRF via redirect chains
    [HttpGet("track-shipment")]
    public async Task<IActionResult> TrackShipment([FromQuery] string carrierUrl, [FromQuery] string trackingNumber)
    {
        var request = (HttpWebRequest)WebRequest.Create(carrierUrl + "?tracking=" + trackingNumber);
        request.Method = "GET";
        using var webResponse = (HttpWebResponse)request.GetResponse();
        using var reader = new System.IO.StreamReader(webResponse.GetResponseStream());
        string result = await reader.ReadToEndAsync();
        return Ok(result);
    }
}
