package shop;
import java.io.*;
import java.nio.file.*;
public class DownloadController {
    private final File root = new File("/var/data/files");
    public byte[] download(String fileName) throws IOException {
        File target = new File(root, fileName);
        return Files.readAllBytes(target.toPath());
    }
}
