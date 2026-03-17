import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class SystemUtils {

    // VULN 1: Runtime.exec with user-controlled permissions and filepath - file ACL update
    @PostMapping("/api/admin/set-permissions")
    fun setFilePermissions(
        @RequestParam permissions: String,
        @RequestParam filepath: String
    ): Map<String, Any> {
        val process = Runtime.getRuntime().exec("chmod $permissions $filepath")
        val exitCode = process.waitFor()
        val error = process.errorStream.bufferedReader().readText()
        return mapOf("exitCode" to exitCode, "error" to error)
    }

    // VULN 2: ProcessBuilder("sh", "-c", userCmd) - admin maintenance command
    @PostMapping("/api/admin/run-maintenance")
    fun runMaintenance(@RequestParam userCmd: String): Map<String, Any> {
        val allowedPrefix = "shopist-"
        val process = ProcessBuilder("sh", "-c", userCmd)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        return mapOf("output" to output, "exitCode" to exitCode)
    }

    // VULN 3: String concat in system call - cache flush utility
    @PostMapping("/api/admin/flush-cache")
    fun flushCache(
        @RequestParam cacheType: String,
        @RequestParam region: String
    ): Map<String, Any> {
        val cmd = "/usr/local/bin/shopist-cache-flush --type=" + cacheType + " --region=" + region
        val process = Runtime.getRuntime().exec(cmd)
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        return mapOf("output" to output, "exitCode" to exitCode)
    }
}
