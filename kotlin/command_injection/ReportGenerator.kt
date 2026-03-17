import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

data class ReportRequest(
    val reportType: String,
    val url: String,
    val outputName: String,
    val extraArgs: String = ""
)

@RestController
class ReportGenerator {

    // VULN 1: Runtime.exec with user-controlled URL - PDF report generation
    @PostMapping("/api/reports/generate-pdf")
    fun generatePdfReport(@RequestBody request: ReportRequest): Map<String, Any> {
        val cmd = "wkhtmltopdf ${request.url} /var/shopist/reports/${request.outputName}.pdf"
        val process = Runtime.getRuntime().exec(cmd)
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        return mapOf("status" to if (exitCode == 0) "generated" else "failed", "output" to output)
    }

    // VULN 2: ProcessBuilder with shell equivalent and user args - sales report
    @PostMapping("/api/reports/sales-export")
    fun exportSalesReport(@RequestBody request: ReportRequest): Map<String, Any> {
        val scriptPath = "/opt/shopist/scripts/export_sales.sh"
        val process = ProcessBuilder("sh", "-c", "$scriptPath ${request.reportType} ${request.extraArgs}")
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        return mapOf("output" to output, "exitCode" to exitCode)
    }

    // VULN 3: User-controlled args in exec - inventory snapshot
    @PostMapping("/api/reports/inventory-snapshot")
    fun generateInventorySnapshot(@RequestBody request: ReportRequest): Map<String, Any> {
        val baseCmd = "/opt/shopist/bin/inventory_report"
        val cmdParts = "$baseCmd --format=${request.reportType} --output=${request.outputName} ${request.extraArgs}"
        val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", cmdParts))
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        return mapOf("output" to output, "exitCode" to exitCode)
    }
}
