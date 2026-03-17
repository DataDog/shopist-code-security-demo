import java.io.*;

public class FileOperations {
    // VULN 1: Runtime.exec with string concatenation - file conversion
    public void convertFileFormat(String inputFile, String outputFormat) throws IOException {
        Runtime.getRuntime().exec("convert " + inputFile + " output." + outputFormat);
    }

    // VULN 2: ProcessBuilder sh -c with string concatenation - create zip archive
    public void createArchive(String directory, String archiveName) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "zip -r " + archiveName + ".zip " + directory);
        pb.start();
    }

    // VULN 3: Runtime.exec array form with string concatenation - chmod
    public void setFilePermissions(String filepath, String permissions) throws IOException {
        String[] cmd = {"sh", "-c", "chmod " + permissions + " " + filepath};
        Runtime.getRuntime().exec(cmd);
    }
}
