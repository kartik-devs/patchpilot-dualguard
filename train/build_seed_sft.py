"""Generate a small, tracked, instruction-formatted SFT seed set for the fixer.

This is a BOOTSTRAP dataset — a handful of clean vulnerable→fixed Java pairs across
the Semgrep/CodeQL-covered CWEs — so a LoRA fine-tune is guaranteed to run tonight
in one command, even if the full public-corpus prep (`make prep` over CVEfixes /
JavaVFC) is fiddly. The real run uses the larger deduped, leakage-free corpus; this
seed proves the pipeline end-to-end and gives a directional before/after.

Output: ``train/seed_sft.jsonl`` (tracked — travels with the repo to the pod).
Each line: {"cwe","prompt","completion"} consumed by train/finetune_lora.py
(build_chat_messages maps prompt→user, completion→assistant).

Run:  python -m train.build_seed_sft
"""

from __future__ import annotations

import json
import os
from typing import List, Tuple

_INSTR = (
    "You are given a Java method with a {cwe} vulnerability. Return the COMPLETE "
    "corrected method. Fix only the vulnerability; preserve behavior; do not delete "
    "functionality. Output only the fixed Java in a ```java block."
)

# (cwe_label, vulnerable, fixed) — short, realistic, behavior-preserving fixes.
PAIRS: List[Tuple[str, str, str]] = [
    ("CWE-89 SQL injection",
     'public ResultSet find(Connection c, String name) throws Exception {\n'
     '    Statement st = c.createStatement();\n'
     '    return st.executeQuery("SELECT * FROM users WHERE name = \'" + name + "\'");\n}',
     'public ResultSet find(Connection c, String name) throws Exception {\n'
     '    PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE name = ?");\n'
     '    ps.setString(1, name);\n'
     '    return ps.executeQuery();\n}'),

    ("CWE-89 SQL injection",
     'public int delete(Connection c, String id) throws Exception {\n'
     '    Statement st = c.createStatement();\n'
     '    return st.executeUpdate("DELETE FROM orders WHERE id = " + id);\n}',
     'public int delete(Connection c, String id) throws Exception {\n'
     '    PreparedStatement ps = c.prepareStatement("DELETE FROM orders WHERE id = ?");\n'
     '    ps.setString(1, id);\n'
     '    return ps.executeUpdate();\n}'),

    ("CWE-22 path traversal",
     'public byte[] read(String base, String name) throws IOException {\n'
     '    File f = new File(base, name);\n'
     '    return Files.readAllBytes(f.toPath());\n}',
     'public byte[] read(String base, String name) throws IOException {\n'
     '    File baseDir = new File(base).getCanonicalFile();\n'
     '    File f = new File(baseDir, name).getCanonicalFile();\n'
     '    if (!f.toPath().startsWith(baseDir.toPath())) {\n'
     '        throw new IOException("path traversal blocked: " + name);\n'
     '    }\n'
     '    return Files.readAllBytes(f.toPath());\n}'),

    ("CWE-78 OS command injection",
     'public Process run(String userInput) throws IOException {\n'
     '    return Runtime.getRuntime().exec("ping " + userInput);\n}',
     'public Process run(String userInput) throws IOException {\n'
     '    if (!userInput.matches("[A-Za-z0-9_.-]+")) {\n'
     '        throw new IllegalArgumentException("invalid host");\n'
     '    }\n'
     '    return new ProcessBuilder("ping", userInput).start();\n}'),

    ("CWE-79 cross-site scripting",
     'public void render(HttpServletResponse resp, String comment) throws IOException {\n'
     '    resp.getWriter().println("<div>" + comment + "</div>");\n}',
     'public void render(HttpServletResponse resp, String comment) throws IOException {\n'
     '    String safe = org.owasp.encoder.Encode.forHtml(comment);\n'
     '    resp.getWriter().println("<div>" + safe + "</div>");\n}'),

    ("CWE-327 weak cryptographic algorithm",
     'public byte[] digest(byte[] data) throws Exception {\n'
     '    MessageDigest md = MessageDigest.getInstance("MD5");\n'
     '    return md.digest(data);\n}',
     'public byte[] digest(byte[] data) throws Exception {\n'
     '    MessageDigest md = MessageDigest.getInstance("SHA-256");\n'
     '    return md.digest(data);\n}'),

    ("CWE-327 weak cryptographic algorithm",
     'public Cipher cipher() throws Exception {\n'
     '    return Cipher.getInstance("DES");\n}',
     'public Cipher cipher() throws Exception {\n'
     '    return Cipher.getInstance("AES/GCM/NoPadding");\n}'),

    ("CWE-611 XML external entity (XXE)",
     'public Document parse(InputStream in) throws Exception {\n'
     '    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n'
     '    return f.newDocumentBuilder().parse(in);\n}',
     'public Document parse(InputStream in) throws Exception {\n'
     '    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n'
     '    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
     '    f.setExpandEntityReferences(false);\n'
     '    return f.newDocumentBuilder().parse(in);\n}'),

    ("CWE-502 unsafe deserialization",
     'public Object load(InputStream in) throws Exception {\n'
     '    ObjectInputStream ois = new ObjectInputStream(in);\n'
     '    return ois.readObject();\n}',
     'public Object load(InputStream in) throws Exception {\n'
     '    ObjectInputStream ois = new ObjectInputStream(in) {\n'
     '        protected Class<?> resolveClass(ObjectStreamClass d) throws IOException, ClassNotFoundException {\n'
     '            if (!d.getName().equals(Account.class.getName())) {\n'
     '                throw new InvalidClassException("unauthorized class", d.getName());\n'
     '            }\n'
     '            return super.resolveClass(d);\n'
     '        }\n'
     '    };\n'
     '    return ois.readObject();\n}'),

    ("CWE-90 LDAP injection",
     'public NamingEnumeration<SearchResult> search(DirContext ctx, String user) throws Exception {\n'
     '    return ctx.search("ou=people", "(uid=" + user + ")", new SearchControls());\n}',
     'public NamingEnumeration<SearchResult> search(DirContext ctx, String user) throws Exception {\n'
     '    String safe = user.replaceAll("[*()\\\\\\u0000]", "");\n'
     '    return ctx.search("ou=people", "(uid={0})", new Object[]{safe}, new SearchControls());\n}'),
]


def build(out_path: str = None) -> str:
    out_path = out_path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "seed_sft.jsonl")
    with open(out_path, "w", encoding="utf-8") as fh:
        for cwe, vuln, fixed in PAIRS:
            rec = {
                "cwe": cwe,
                "prompt": _INSTR.format(cwe=cwe) + "\n\n```java\n" + vuln + "\n```",
                "completion": "```java\n" + fixed + "\n```",
            }
            fh.write(json.dumps(rec) + "\n")
    return out_path


if __name__ == "__main__":
    p = build()
    print(f"wrote {len(PAIRS)} seed SFT pairs -> {p}")
