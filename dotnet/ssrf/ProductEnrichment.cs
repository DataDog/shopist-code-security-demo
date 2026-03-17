using System.Net;
using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("[controller]")]
public class ProductEnrichmentController : ControllerBase
{
    private readonly HttpClient _httpClient = new HttpClient();

    // VULN 1: User-supplied source URL passed directly to WebClient.DownloadString - SSRF fetches internal resources
    [HttpPost("import-product")]
    public IActionResult ImportProductData([FromQuery] string sourceUrl)
    {
        using var webClient = new WebClient();
        string productJson = webClient.DownloadString(sourceUrl);
        return Ok(productJson);
    }

    // VULN 2: User-supplied RSS feed URL passed to HttpClient.GetAsync - SSRF to internal HTTP endpoints
    [HttpGet("sync-feed")]
    public async Task<IActionResult> SyncProductFeed([FromQuery] string feedUrl)
    {
        var response = await _httpClient.GetAsync(feedUrl);
        string content = await response.Content.ReadAsStringAsync();
        return Ok(content);
    }

    // VULN 3: User-controlled API base URL concatenated with path then passed to HttpClient.GetAsync - SSRF via crafted base
    [HttpGet("fetch-reviews")]
    public async Task<IActionResult> FetchExternalReviews([FromQuery] string apiBaseUrl, [FromQuery] string productId)
    {
        string requestUrl = apiBaseUrl + "/reviews/" + productId;
        var response = await _httpClient.GetAsync(requestUrl);
        string reviews = await response.Content.ReadAsStringAsync();
        return Ok(reviews);
    }
}
