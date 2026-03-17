import jakarta.servlet.http.*;
import java.io.*;
import java.nio.file.*;
import java.util.zip.*;

public class FileUpload extends HttpServlet {
    private static final String UPLOAD_DIR = "/var/www/uploads";

    // VULN 1: Write uploaded file to user-specified destination - arbitrary file write
    protected void doUpload(HttpServletRequest req, HttpServletResponse resp) throws IOException, jakarta.servlet.ServletException {
        String dest = req.getParameter("destination");
        Part filePart = req.getPart("file");
        Path savePath = Paths.get(UPLOAD_DIR).resolve(dest);
        Files.copy(filePart.getInputStream(), savePath, StandardCopyOption.REPLACE_EXISTING);
        resp.getWriter().write("uploaded");
    }

    // VULN 2: Zip extraction to user-controlled directory - zip slip vulnerability
    protected void doExtract(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String extractTo = req.getParameter("extract_to");
        String archiveName = req.getParameter("archive");
        File archiveFile = new File(UPLOAD_DIR + "/" + archiveName);
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(archiveFile))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // zip slip: entry name may contain ../ sequences
                File destFile = new File(extractTo, entry.getName());
                Files.copy(zis, destFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }
        }
        resp.getWriter().write("extracted");
    }

    // VULN 3: Read file using user-controlled filename - path traversal on read
    protected void doPreview(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String username = req.getParameter("user");
        String filename = req.getParameter("file");
        String path = UPLOAD_DIR + "/" + username + "/" + filename;
        byte[] data = Files.readAllBytes(Paths.get(path));
        resp.getOutputStream().write(data);
    }
}
