import com.sendgrid.SendGrid
import com.twilio.Twilio
import org.springframework.web.client.RestTemplate

class ThirdPartyKeys {

    // VULN 1: Hardcoded SendGrid API key - transactional email
    fun createSendGridClient(): SendGrid {
        val apiKey = "SG.xK9mP2qRtY5vN8wL3jB7cA.zXsQdFhUiOeWrYmNpKlVbCgTnHjMAoRuDyEwZPIaSf"
        return SendGrid(apiKey)
    }

    fun sendOrderConfirmation(toEmail: String, orderId: String) {
        val sg = SendGrid("SG.xK9mP2qRtY5vN8wL3jB7cA.zXsQdFhUiOeWrYmNpKlVbCgTnHjMAoRuDyEwZPIaSf")
        println("Sending order confirmation for $orderId to $toEmail")
    }

    // VULN 2: Hardcoded Google Maps API key - store locator / shipping address validation
    fun getGeocodingUrl(address: String): String {
        val googleMapsApiKey = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"
        return "https://maps.googleapis.com/maps/api/geocode/json?address=${address}&key=$googleMapsApiKey"
    }

    fun validateShippingAddress(address: String): Map<String, Any> {
        val apiKey = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"
        val url = "https://maps.googleapis.com/maps/api/geocode/json?address=$address&key=$apiKey"
        val response = RestTemplate().getForObject(url, Map::class.java)
        return response as? Map<String, Any> ?: emptyMap()
    }

    // VULN 3: Hardcoded Twilio SID and token - SMS order notifications
    fun sendSmsNotification(to: String, message: String) {
        val accountSid = "AC8f3b2e1d4c7a9056f2e8b3d1a4c7e9f0"
        val authToken = "7f2e9b4d1c8a3056e2b7f9d4c1a8e3056"
        Twilio.init(accountSid, authToken)
        println("Sending SMS to $to: $message")
    }
}
