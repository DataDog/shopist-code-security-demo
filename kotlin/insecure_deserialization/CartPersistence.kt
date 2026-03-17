import jakarta.servlet.http.HttpServletRequest
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.multipart.MultipartFile
import java.io.ByteArrayInputStream
import java.io.ObjectInputStream
import java.util.Base64

data class CartItem(val productId: String, val quantity: Int, val price: Double)

@RestController
class CartPersistence {

    // VULN 1: ObjectInputStream deserialization from Base64 cookie - RCE via cookie manipulation
    @GetMapping("/api/cart/restore")
    fun restoreCartFromCookie(request: HttpServletRequest): Any {
        val cartCookie = request.cookies?.firstOrNull { it.name == "cart_data" }?.value
            ?: return mapOf("items" to emptyList<CartItem>())
        val bytes = Base64.getDecoder().decode(cartCookie)
        val ois = ObjectInputStream(ByteArrayInputStream(bytes))
        val cart = ois.readObject()
        ois.close()
        return cart
    }

    // VULN 2: ObjectInputStream deserialization from raw request body - cart sync endpoint
    @PostMapping("/api/cart/sync")
    fun syncCartFromRequest(request: HttpServletRequest): Map<String, Any> {
        val ois = ObjectInputStream(request.inputStream)
        val cartData = ois.readObject()
        ois.close()
        return mapOf("status" to "synced", "cart" to (cartData as? List<*> ?: emptyList<Any>()))
    }

    // VULN 3: ObjectInputStream on uploaded file - cart import feature
    @PostMapping("/api/cart/import")
    fun importCartFromFile(
        @RequestParam("cartFile") file: MultipartFile
    ): Map<String, Any> {
        val ois = ObjectInputStream(file.inputStream)
        val importedCart = ois.readObject()
        ois.close()
        return mapOf("status" to "imported", "itemCount" to (importedCart as? List<*>)?.size)
    }
}
