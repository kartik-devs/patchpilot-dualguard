"""Write a small HELD-OUT set of vulnerable Java files for the quick Semgrep eval.

These are DELIBERATELY different from train/seed_sft.jsonl (different class/method
names + scenarios) so the fine-tuned model is tested on data it did not train on.
Each file has exactly one well-covered CWE that Semgrep Community detects, so the
quick eval (eval/quick_eval.py) can prove a real red->green on actual code without
needing Vul4J.

Run:  python -m eval.build_samples   ->  writes eval/samples/*.java + manifest.json
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Tuple

# (filename, cwe, vulnerable Java source)
SAMPLES: List[Tuple[str, str, str]] = [
    ("LoginDao.java", "CWE-89", """package shop;
import java.sql.*;
public class LoginDao {
    private final Connection conn;
    public LoginDao(Connection c) { this.conn = c; }
    public boolean authenticate(String user, String pass) throws Exception {
        Statement st = conn.createStatement();
        String sql = "SELECT id FROM accounts WHERE user = '" + user + "' AND pass = '" + pass + "'";
        ResultSet rs = st.executeQuery(sql);
        return rs.next();
    }
}
"""),
    ("ProfileServlet.java", "CWE-79", """package shop;
import java.io.*;
import javax.servlet.http.*;
public class ProfileServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String nick = req.getParameter("nick");
        PrintWriter out = resp.getWriter();
        out.println("<h1>Hello " + nick + "</h1>");
    }
}
"""),
    ("DownloadController.java", "CWE-22", """package shop;
import java.io.*;
import java.nio.file.*;
public class DownloadController {
    private final File root = new File("/var/data/files");
    public byte[] download(String fileName) throws IOException {
        File target = new File(root, fileName);
        return Files.readAllBytes(target.toPath());
    }
}
"""),
    ("BackupRunner.java", "CWE-78", """package ops;
import java.io.*;
public class BackupRunner {
    public Process archive(String dir) throws IOException {
        String cmd = "tar -czf /tmp/backup.tgz " + dir;
        return Runtime.getRuntime().exec(cmd);
    }
}
"""),
    ("PasswordHasher.java", "CWE-327", """package auth;
import java.security.*;
public class PasswordHasher {
    public String hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] out = md.digest(password.getBytes("UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (byte b : out) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
"""),
    ("FeedParser.java", "CWE-611", """package feed;
import javax.xml.parsers.*;
import org.w3c.dom.Document;
import java.io.InputStream;
public class FeedParser {
    public Document parse(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(in);
    }
}
"""),
]


def build(out_dir: str = None) -> Dict[str, str]:
    out_dir = out_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")
    os.makedirs(out_dir, exist_ok=True)
    manifest = []
    for fname, cwe, src in SAMPLES:
        with open(os.path.join(out_dir, fname), "w", encoding="utf-8") as fh:
            fh.write(src)
        manifest.append({"file": fname, "cwe": cwe})
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return {"out_dir": out_dir, "count": str(len(SAMPLES))}


if __name__ == "__main__":
    r = build()
    print(f"wrote {r['count']} held-out vulnerable Java samples -> {r['out_dir']}")
