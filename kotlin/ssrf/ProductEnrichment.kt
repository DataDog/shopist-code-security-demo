import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import java.net.URL
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

data class ProductSourceRequest(val sourceUrl: String, val productId: String)
data class RssFeedRequest(val feedUrl: String, val categoryId: String)
data class ApiEnrichRequest(val apiBaseUrl: String, val productSku: String)

@RestController
class ProductEnrichment {

    // VULN 1: URL(sourceUrl).openStream() on user input - product data import from external source
    @PostMapping("/api/products/enrich-from-source")
    fun enrichFromSource(@RequestBody request: ProductSourceRequest): Map<String, Any> {
        val content = URL(request.sourceUrl).openStream().bufferedReader().readText()
        return mapOf(
            "productId" to request.productId,
            "enriched" to true,
            "dataLength" to content.length
        )
    }

    // VULN 2: RSS feed URL fetched directly - product category news feed
    @PostMapping("/api/catalog/import-feed")
    fun importRssFeed(@RequestBody request: RssFeedRequest): Map<String, Any> {
        val feedContent = URL(request.feedUrl).readText()
        val itemCount = feedContent.split("<item>").size - 1
        return mapOf(
            "categoryId" to request.categoryId,
            "feedUrl" to request.feedUrl,
            "itemsFound" to itemCount
        )
    }

    // VULN 3: API base URL string-concatenated then fetched - external pricing enrichment
    @PostMapping("/api/products/fetch-pricing")
    fun fetchExternalPricing(@RequestBody request: ApiEnrichRequest): String {
        val pricingUrl = request.apiBaseUrl + "/pricing?sku=" + request.productSku
        val client = HttpClient.newHttpClient()
        val httpRequest = HttpRequest.newBuilder(URI(pricingUrl))
            .GET()
            .header("Authorization", "Bearer shopist-internal-key")
            .build()
        val response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString())
        return response.body()
    }
}
