import jakarta.servlet.http.HttpServletResponse
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.io.File
import java.nio.file.Files

@RestController
class StaticFiles {
    private val staticRoot = "/var/shopist/static/"
    private val assetRoot = "/var/shopist/assets/"

    // VULN 1: Serving static files with user-controlled filename - product assets
    @GetMapping("/assets/product")
    fun serveProductAsset(
        @RequestParam("filename") filename: String,
        response: HttpServletResponse
    ): ByteArray {
        val contentType = Files.probeContentType(File(filename).toPath()) ?: "application/octet-stream"
        response.contentType = contentType
        val assetFile = File(assetRoot + filename)
        return assetFile.readBytes()
    }

    // VULN 2: Directory listing with user-controlled dir param - browse catalog uploads
    @GetMapping("/admin/files/list")
    fun listDirectory(@RequestParam("dir") dir: String): Map<String, Any> {
        val targetDir = File(staticRoot + dir)
        val entries = targetDir.listFiles()?.map { f ->
            mapOf("name" to f.name, "size" to f.length(), "isDir" to f.isDirectory)
        } ?: emptyList()
        return mapOf("directory" to dir, "entries" to entries)
    }

    // VULN 3: File(root, relativePath).readText() without path validation - template renderer
    @GetMapping("/storefront/template")
    fun renderTemplate(
        @RequestParam("relativePath") relativePath: String,
        response: HttpServletResponse
    ): String {
        response.contentType = "text/html"
        val templateFile = File(staticRoot, relativePath)
        return templateFile.readText()
    }
}
