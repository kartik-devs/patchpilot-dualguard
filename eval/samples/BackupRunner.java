package ops;
import java.io.*;
public class BackupRunner {
    public Process archive(String dir) throws IOException {
        String cmd = "tar -czf /tmp/backup.tgz " + dir;
        return Runtime.getRuntime().exec(cmd);
    }
}
