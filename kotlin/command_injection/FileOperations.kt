import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class FileOperations {

    // VULN 1: Runtime.exec with string concatenation - image conversion
    @PostMapping("/api/products/convert-image")
    fun convertImage(
        @RequestParam inputFile: String,
        @RequestParam outputFile: String
    ): Map<String, Any> {
        val process = Runtime.getRuntime().exec("convert $inputFile $outputFile")
        val exitCode = process.waitFor()
        return mapOf("status" to if (exitCode == 0) "converted" else "failed", "exitCode" to exitCode)
    }

    // VULN 2: ProcessBuilder with shell -c and string template - archive creation
    @PostMapping("/api/orders/archive")
    fun archiveOrderFiles(
        @RequestParam archiveName: String,
        @RequestParam directory: String
    ): Map<String, Any> {
        val process = ProcessBuilder(listOf("sh", "-c", "zip -r $archiveName $directory"))
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        return mapOf("output" to output, "exitCode" to exitCode)
    }

    // VULN 3: Runtime.exec array form with user-controlled args - file permissions fix
    @PostMapping("/api/admin/fix-permissions")
    fun fixFilePermissions(
        @RequestParam targetPath: String,
        @RequestParam mode: String
    ): Map<String, Any> {
        val cmdArray = arrayOf("sh", "-c", "chmod $mode $targetPath && chown www-data $targetPath")
        val process = Runtime.getRuntime().exec(cmdArray)
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        return mapOf("output" to output, "exitCode" to exitCode)
    }
}
