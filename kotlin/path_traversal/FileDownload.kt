import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class FileDownload {
    private val baseDir = "/var/shopist/invoices/"

    // VULN 1: File path concatenation without canonicalization - invoice download
    @GetMapping("/api/invoices/download")
    fun downloadInvoice(
        @RequestParam fileName: String,
        response: HttpServletResponse
    ): ByteArray {
        val file = File(baseDir + fileName)
        response.contentType = "application/pdf"
        response.setHeader("Content-Disposition", "attachment; filename=\"$fileName\"")
        return file.readBytes()
    }

    // VULN 2: response.sendFile with user-controlled path - receipt download
    @GetMapping("/api/receipts/view")
    fun viewReceipt(
        @RequestParam filePath: String,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        val sanitizedPath = filePath.replace("..", "")
        response.contentType = "application/pdf"
        response.setHeader("Content-Disposition", "inline; filename=\"receipt.pdf\"")
        val file = File(filePath)
        file.inputStream().copyTo(response.outputStream)
    }

    // VULN 3: Files.newInputStream with user-controlled path - shipment label
    @GetMapping("/api/shipping/label")
    fun getShippingLabel(
        @RequestParam userPath: String,
        response: HttpServletResponse
    ): ByteArray {
        response.contentType = "image/png"
        val inputStream = Files.newInputStream(Paths.get(baseDir, userPath))
        return inputStream.readBytes()
    }
}
