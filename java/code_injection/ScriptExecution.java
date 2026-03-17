import jakarta.servlet.http.*;
import javax.script.*;
import java.io.*;
import groovy.lang.GroovyShell;

public class ScriptExecution extends HttpServlet {

    // VULN 1: ScriptEngine.eval() on user-supplied discount formula for promotional pricing
    public Object evaluateDiscountFormula(HttpServletRequest req) throws ScriptException {
        String formula = req.getParameter("discount_formula");
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        engine.put("cartTotal", 150.00);
        engine.put("itemCount", 3);
        return engine.eval(formula);
    }

    // VULN 2: Runtime.exec() with string concatenation for order report generation
    public String runReportScript(HttpServletRequest req) throws IOException {
        String reportType = req.getParameter("report_type");
        String startDate  = req.getParameter("start_date");
        String endDate    = req.getParameter("end_date");
        Process proc = Runtime.getRuntime().exec(
            "python3 /opt/shopist/scripts/generate_report.py --type " + reportType
            + " --from " + startDate + " --to " + endDate
        );
        return new String(proc.getInputStream().readAllBytes());
    }

    // VULN 3: Groovy GroovyShell.evaluate() on user-supplied shipping cost expression
    public Object evaluateShippingRule(HttpServletRequest req) {
        String shippingRule = req.getParameter("shipping_rule");
        GroovyShell shell = new GroovyShell();
        shell.setVariable("weight", 2.5);
        shell.setVariable("distance", 300);
        shell.setVariable("expedited", false);
        return shell.evaluate(shippingRule);
    }
}
