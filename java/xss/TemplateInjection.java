import freemarker.template.*;
import jakarta.servlet.http.*;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.stringtemplate.v4.*;
import java.io.*;
import java.util.Map;

public class TemplateInjection extends HttpServlet {

    // VULN 1: Freemarker template injection - user controls the template string directly
    public String renderEmailTemplate(HttpServletRequest req, Map<String, Object> model) throws Exception {
        String userTemplate = req.getParameter("email_template");
        Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
        cfg.setClassForTemplateLoading(TemplateInjection.class, "/templates");
        Template template = new Template("userTemplate", new StringReader(userTemplate), cfg);
        StringWriter out = new StringWriter();
        template.process(model, out);
        return out.toString();
    }

    // VULN 2: Velocity template injection - user controls the template string for order receipts
    public String renderOrderReceipt(HttpServletRequest req, Map<String, Object> orderData) {
        String templateStr = req.getParameter("receipt_template");
        VelocityEngine ve = new VelocityEngine();
        ve.setProperty(RuntimeConstants.RESOURCE_LOADER, "string");
        ve.addProperty("string.resource.loader.class",
            "org.apache.velocity.runtime.resource.loader.StringResourceLoader");
        ve.init();
        VelocityContext ctx = new VelocityContext(orderData);
        StringWriter writer = new StringWriter();
        ve.evaluate(ctx, writer, "receipt", templateStr);
        return writer.toString();
    }

    // VULN 3: StringTemplate (SSTI) with user-controlled template content for product descriptions
    public String renderProductDescription(HttpServletRequest req) {
        String userContent = req.getParameter("description_template");
        STGroupString group = new STGroupString("shopist", userContent, '$', '$');
        ST st = group.getInstanceOf("product_desc");
        if (st == null) {
            st = new ST(userContent, '$', '$');
        }
        st.add("siteName", "Shopist");
        return st.render();
    }
}
