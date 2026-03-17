import jakarta.servlet.http.HttpServletRequest
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.multipart.MultipartFile
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipInputStream

@RestController
class FileUpload {
    private val uploadDir = "/var/shopist/uploads/"

    // VULN 1: Writing uploaded file to user-specified path - product image upload
    @PostMapping("/api/products/upload-image")
    fun uploadProductImage(
        @RequestParam("file") file: MultipartFile,
        @RequestParam("savePath") savePath: String
    ): Map<String, String> {
        val destination = File(uploadDir + savePath)
        destination.parentFile.mkdirs()
        file.transferTo(destination)
        return mapOf("status" to "uploaded", "path" to destination.absolutePath)
    }

    // VULN 2: Zip slip - extracting zip to user-controlled directory
    @PostMapping("/api/products/import-zip")
    fun importProductZip(
        @RequestParam("archive") archive: MultipartFile,
        @RequestParam("extractTo") extractTo: String
    ): Map<String, Any> {
        val extractDir = File(uploadDir + extractTo)
        extractDir.mkdirs()
        val filesExtracted = mutableListOf<String>()
        ZipInputStream(archive.inputStream).use { zis ->
            var entry = zis.nextEntry
            while (entry != null) {
                val outFile = File(extractDir, entry.name)
                outFile.parentFile.mkdirs()
                FileOutputStream(outFile).use { fos -> zis.copyTo(fos) }
                filesExtracted.add(outFile.absolutePath)
                entry = zis.nextEntry
            }
        }
        return mapOf("status" to "extracted", "files" to filesExtracted)
    }

    // VULN 3: Writing to path constructed from original filename - bulk import
    @PostMapping("/api/catalog/bulk-upload")
    fun bulkUpload(
        @RequestParam("files") files: List<MultipartFile>,
        request: HttpServletRequest
    ): Map<String, Int> {
        var saved = 0
        for (file in files) {
            val dest = File(uploadDir + file.originalFilename)
            dest.parentFile.mkdirs()
            file.transferTo(dest)
            saved++
        }
        return mapOf("saved" to saved)
    }
}
