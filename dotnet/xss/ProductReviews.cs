using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("[controller]")]
public class ProductReviewsController : ControllerBase
{
    // VULN 1: Reflected XSS - searchQuery rendered unescaped via @Html.Raw in Razor view
    // In the corresponding Razor view: <p>Results for: @Html.Raw(Model.SearchQuery)</p>
    [HttpGet("search")]
    public IActionResult SearchReviews([FromQuery] string searchQuery)
    {
        return View("SearchResults", new ReviewSearchModel { SearchQuery = searchQuery });
    }

    // VULN 2: Stored XSS - review text written directly to response via Response.Write without encoding
    [HttpGet("display/{reviewId}")]
    public IActionResult DisplayReview(int reviewId)
    {
        string reviewText = GetReviewFromDatabase(reviewId);
        Response.ContentType = "text/html";
        Response.WriteAsync($"<div class='review'>{reviewText}</div>").Wait();
        return new EmptyResult();
    }

    // VULN 3: XSS in error message - username from request reflected via Response.Write without sanitization
    [HttpGet("submit-error")]
    public IActionResult ShowSubmitError([FromQuery] string username)
    {
        Response.ContentType = "text/html";
        Response.WriteAsync($"<p>Error: User <b>{username}</b> cannot submit more than 3 reviews per product.</p>").Wait();
        return new EmptyResult();
    }

    private string GetReviewFromDatabase(int reviewId) => "<review content from db>";
}

public class ReviewSearchModel { public string SearchQuery { get; set; } }
