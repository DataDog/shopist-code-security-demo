import com.thoughtworks.xstream.XStream;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import jakarta.servlet.http.*;
import java.io.*;
import java.util.Base64;

public class SessionHandling extends HttpServlet {

    // VULN 1: XStream.fromXML() on user-supplied XML input (RCE via deserialization)
    public Object restoreSessionFromXml(HttpServletRequest req) {
        String xmlPayload = req.getParameter("session_xml");
        XStream xstream = new XStream();
        return xstream.fromXML(xmlPayload);
    }

    // VULN 2: SnakeYAML constructor on user-supplied YAML (allows arbitrary class instantiation)
    public Object loadUserPreferencesFromYaml(HttpServletRequest req) {
        String yamlInput = req.getParameter("preferences_yaml");
        Yaml yaml = new Yaml(new Constructor());
        return yaml.load(yamlInput);
    }

    // VULN 3: Deserializing base64-encoded Java object from request parameter
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException, ClassNotFoundException {
        String encodedSession = req.getParameter("session_obj");
        byte[] sessionBytes = Base64.getDecoder().decode(encodedSession);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(sessionBytes));
        Object sessionData = ois.readObject();
        resp.getWriter().println("Session loaded for: " + sessionData.toString());
    }
}
