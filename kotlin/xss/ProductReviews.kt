import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

data class Review(val productId: String, val username: String, val reviewText: String, val rating: Int)

@RestController
class ProductReviews {
    private val storedReviews = mutableListOf<Review>()

    // VULN 1: Reflected XSS - search results page reflects unsanitized query
    @GetMapping("/shop/search")
    fun searchProducts(
        @RequestParam("q") query: String,
        response: HttpServletResponse
    ) {
        response.contentType = "text/html"
        val writer = response.writer
        writer.println("<html><body>")
        writer.println("<h1>Results for: $query</h1>")
        writer.println("<p>Showing products matching your search.</p>")
        writer.println("</body></html>")
    }

    // VULN 2: Stored XSS - product review text stored and re-rendered without sanitization
    @PostMapping("/api/products/review")
    fun submitReview(@RequestParam productId: String, @RequestParam reviewText: String, @RequestParam rating: Int, request: HttpServletRequest) {
        val username = request.session?.getAttribute("username") as? String ?: "anonymous"
        storedReviews.add(Review(productId, username, reviewText, rating))
    }

    @GetMapping("/shop/product/reviews")
    fun renderReviews(@RequestParam("productId") productId: String, response: HttpServletResponse) {
        response.contentType = "text/html"
        val writer = response.writer
        writer.println("<html><body><ul>")
        storedReviews.filter { it.productId == productId }.forEach { review ->
            writer.write("<li><strong>${review.username}</strong>: ${review.reviewText} (${review.rating}/5)</li>")
        }
        writer.println("</ul></body></html>")
    }

    // VULN 3: Reflected XSS via username in error message
    @GetMapping("/shop/product/review-error")
    fun reviewError(
        @RequestParam("username") username: String,
        @RequestParam("reason") reason: String,
        response: HttpServletResponse
    ) {
        response.contentType = "text/html"
        response.writer.println(
            "<html><body><div class='error'>Sorry $username, your review could not be submitted: $reason</div></body></html>"
        )
    }
}
