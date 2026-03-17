import com.thoughtworks.xstream.XStream
import jakarta.servlet.http.HttpServletRequest
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.yaml.snakeyaml.Yaml
import java.io.ByteArrayInputStream
import java.io.ObjectInputStream
import java.util.Base64

@RestController
class SessionHandling {

    // VULN 1: SnakeYAML deserialization of user-controlled input - session preferences import
    @PostMapping("/api/session/import-preferences")
    fun importSessionPreferences(@RequestBody yamlInput: String): Map<String, Any> {
        val yaml = Yaml()
        val preferences = yaml.load<Any>(yamlInput)
        return mapOf("status" to "imported", "preferences" to (preferences ?: emptyMap<String, Any>()))
    }

    // VULN 2: XStream deserialization of user-supplied XML - order template import
    @PostMapping("/api/orders/import-template")
    fun importOrderTemplate(@RequestBody xmlInput: String): Map<String, Any> {
        val xstream = XStream()
        val orderTemplate = xstream.fromXML(xmlInput)
        return mapOf("status" to "imported", "template" to orderTemplate)
    }

    // VULN 3: ObjectInputStream from base64-decoded session param - session restore
    @PostMapping("/api/session/restore")
    fun restoreSession(
        @RequestParam("sessionData") sessionData: String,
        request: HttpServletRequest
    ): Map<String, Any> {
        val decoded = Base64.getDecoder().decode(sessionData)
        val ois = ObjectInputStream(ByteArrayInputStream(decoded))
        val sessionObj = ois.readObject()
        ois.close()
        val session = request.getSession(true)
        session.setAttribute("restoredData", sessionObj)
        return mapOf("status" to "restored")
    }
}
