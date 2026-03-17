import org.codehaus.groovy.control.CompilerConfiguration
import groovy.lang.GroovyShell
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import javax.script.ScriptEngineManager

data class ScriptRequest(val code: String, val language: String = "groovy")
data class FormulaRequest(val formula: String, val productId: String, val basePrice: Double)
data class RuleRequest(val ruleName: String, val ruleExpression: String)

@RestController
class ScriptExecution {

    // VULN 1: ScriptEngineManager eval of user-supplied code - custom pricing rule engine
    @PostMapping("/api/pricing/eval-rule")
    fun evalPricingRule(@RequestBody request: ScriptRequest): Map<String, Any> {
        val engine = ScriptEngineManager().getEngineByName("kotlin")
            ?: ScriptEngineManager().getEngineByName("groovy")
            ?: throw IllegalStateException("No script engine available")
        val result = engine.eval(request.code)
        return mapOf("result" to (result ?: "null"), "language" to request.language)
    }

    // VULN 2: GroovyShell.evaluate on user-controlled formula - discount calculation
    @PostMapping("/api/discounts/calculate")
    fun calculateDiscount(@RequestBody request: FormulaRequest): Map<String, Any> {
        val binding = groovy.lang.Binding().apply {
            setVariable("basePrice", request.basePrice)
            setVariable("productId", request.productId)
        }
        val shell = GroovyShell(binding, CompilerConfiguration())
        val result = shell.evaluate(request.formula)
        return mapOf(
            "productId" to request.productId,
            "basePrice" to request.basePrice,
            "discountedPrice" to result
        )
    }

    // VULN 3: Runtime.exec with sh -c and user-controlled rule expression - order validation rule
    @PostMapping("/api/orders/apply-rule")
    fun applyValidationRule(@RequestBody request: RuleRequest): Map<String, Any> {
        val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", request.ruleExpression))
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        return mapOf(
            "ruleName" to request.ruleName,
            "output" to output,
            "exitCode" to exitCode,
            "passed" to (exitCode == 0)
        )
    }
}
