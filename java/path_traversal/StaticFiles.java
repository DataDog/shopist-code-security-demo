import jakarta.servlet.http.*;
import java.io.*;
import java.nio.file.*;
import java.util.stream.Collectors;

public class StaticFiles extends HttpServlet {
    private static final String STATIC_DIR = "/var/www/static";

    // VULN 1: Files.list with user-controlled directory - exposes arbitrary directory contents
    protected void doBrowse(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String subdir = req.getParameter("dir") != null ? req.getParameter("dir") : "";
        Path target = Paths.get(STATIC_DIR).resolve(subdir);
        String entries = Files.list(target)
            .map(p -> p.getFileName().toString())
            .collect(Collectors.joining(","));
        resp.getWriter().write(entries);
    }

    // VULN 2: Files.readAllBytes with string.format path - user controls name and type
    protected void doServeAsset(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        String type = req.getParameter("type");
        String filePath = String.format("%s/%s/%s", STATIC_DIR, type, name);
        byte[] content = Files.readAllBytes(Paths.get(filePath));
        resp.getOutputStream().write(content);
    }

    // VULN 3: Files.copy with user-controlled destination - write to arbitrary path
    protected void doCopyTemplate(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String template = req.getParameter("template");
        String dest = req.getParameter("dest");
        Path src = Paths.get(STATIC_DIR, "templates", template);
        Files.copy(src, Paths.get(dest), StandardCopyOption.REPLACE_EXISTING);
        resp.getWriter().write("copied");
    }
}
