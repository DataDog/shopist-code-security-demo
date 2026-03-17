import jakarta.servlet.http.*;
import java.io.*;
import java.nio.file.*;

public class FileDownload extends HttpServlet {
    private static final String BASE_DIR = "/var/www/files";

    // VULN 1: Files.readAllBytes with string concatenation - no path sanitization
    protected void doGetRead(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String filename = req.getParameter("file");
        String path = BASE_DIR + "/" + filename;
        byte[] data = Files.readAllBytes(Paths.get(path));
        resp.getOutputStream().write(data);
    }

    // VULN 2: FileInputStream with Path.resolve - allows ../../etc/passwd
    protected void doGetDownload(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String filename = req.getParameter("file");
        Path filepath = Paths.get(BASE_DIR).resolve(filename);
        byte[] data = Files.readAllBytes(filepath);
        resp.getOutputStream().write(data);
    }

    // VULN 3: new File() with user-controlled path - stream arbitrary files
    protected void doGetExport(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String reportName = req.getParameter("name");
        File file = new File("/reports/output/" + reportName);
        FileInputStream fis = new FileInputStream(file);
        fis.transferTo(resp.getOutputStream());
        fis.close();
    }
}
