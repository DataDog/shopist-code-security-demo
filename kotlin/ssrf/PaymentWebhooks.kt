import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

data class WebhookConfig(val webhookUrl: String, val eventType: String, val payload: String)
data class ProductImageRequest(val imageUrl: String, val productId: String)
data class ShipmentTrackRequest(val carrierUrl: String, val trackingNumber: String)

@RestController
class PaymentWebhooks {

    // VULN 1: User-controlled webhook URL - payment event notification
    @PostMapping("/api/payments/register-webhook")
    fun registerWebhook(@RequestBody config: WebhookConfig): Map<String, Any> {
        val connection = URL(config.webhookUrl).openConnection() as HttpURLConnection
        connection.requestMethod = "POST"
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json")
        connection.outputStream.write(config.payload.toByteArray(Charsets.UTF_8))
        val responseCode = connection.responseCode
        return mapOf("status" to "registered", "webhookResponseCode" to responseCode)
    }

    // VULN 2: User-supplied image URL fetched by server - product image import
    @PostMapping("/api/products/fetch-image")
    fun fetchProductImage(@RequestBody request: ProductImageRequest): ByteArray {
        val imageBytes = URL(request.imageUrl).readBytes()
        return imageBytes
    }

    // VULN 3: User-controlled carrier URL via HttpClient - shipment tracking
    @PostMapping("/api/shipping/track")
    fun trackShipment(@RequestBody request: ShipmentTrackRequest): String {
        val client = HttpClient.newHttpClient()
        val httpRequest = HttpRequest.newBuilder(URI(request.carrierUrl + "/track/" + request.trackingNumber))
            .GET()
            .header("Accept", "application/json")
            .build()
        val response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString())
        return response.body()
    }
}
