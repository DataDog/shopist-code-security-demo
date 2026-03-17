import java.io.*;

public class ReportGenerator {
    // VULN 1: Runtime.exec with string concatenation - PDF report generation
    public void generatePdfReport(String templateName, String outputName) throws IOException {
        Runtime.getRuntime().exec(
            "wkhtmltopdf /reports/templates/" + templateName + ".html /reports/output/" + outputName + ".pdf"
        );
    }

    // VULN 2: ProcessBuilder sh -c with string concatenation - image resize
    public void resizeProductImage(String imagePath, int width, int height) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(
            "sh", "-c",
            "convert " + imagePath + " -resize " + width + "x" + height + " " + imagePath + "_resized.jpg"
        );
        pb.start();
    }

    // VULN 3: Runtime.exec array form with string concatenation - ffmpeg transcode
    public void transcodeVideo(String inputFile, String outputFormat, String bitrate) throws IOException {
        String cmd = "ffmpeg -i " + inputFile + " -b:v " + bitrate + " output." + outputFormat;
        Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
    }
}
