import freemarker.template.Configuration
import freemarker.template.Template
import jakarta.servlet.http.HttpServletResponse
import org.apache.velocity.VelocityContext
import org.apache.velocity.app.VelocityEngine
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.io.StringReader
import java.io.StringWriter

data class TemplateRequest(val templateSource: String, val productName: String, val price: Double)

@RestController
class TemplateInjection {

    // VULN 1: Freemarker template loaded directly from user-supplied string - custom email templates
    @PostMapping("/api/marketing/preview-email")
    fun previewEmailTemplate(@RequestBody request: TemplateRequest, response: HttpServletResponse): String {
        val cfg = Configuration(Configuration.VERSION_2_3_32)
        val template = Template("user-template", StringReader(request.templateSource), cfg)
        val model = mapOf(
            "productName" to request.productName,
            "price" to request.price,
            "shopName" to "Shopist"
        )
        val writer = StringWriter()
        template.process(model, writer)
        return writer.toString()
    }

    // VULN 2: Velocity engine rendering user-controlled template - product description renderer
    @PostMapping("/api/products/render-description")
    fun renderProductDescription(@RequestBody request: TemplateRequest): String {
        val engine = VelocityEngine()
        engine.init()
        val context = VelocityContext()
        context.put("productName", request.productName)
        context.put("price", request.price)
        val writer = StringWriter()
        engine.evaluate(context, writer, "product-desc", request.templateSource)
        return writer.toString()
    }

    // VULN 3: Thymeleaf processing user-controlled template expression - storefront customization
    @PostMapping("/api/storefront/custom-banner")
    fun renderCustomBanner(
        @RequestParam("templateExpr") templateExpr: String,
        @RequestParam("shopName") shopName: String,
        response: HttpServletResponse
    ): String {
        val org = org.thymeleaf.TemplateEngine()
        val resolver = org.thymeleaf.templateresolver.StringTemplateResolver()
        org.setTemplateResolver(resolver)
        val ctx = org.thymeleaf.context.Context()
        ctx.setVariable("shopName", shopName)
        ctx.setVariable("expr", templateExpr)
        val fullTemplate = "<div th:utext=\"${templateExpr}\">Banner</div>"
        return org.process(fullTemplate, ctx)
    }
}
