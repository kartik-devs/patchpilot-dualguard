"""MG3: Semgrep JSON + CodeQL SARIF parsing from fixtures."""

from __future__ import annotations

import json
import os

from harness.layers import sast


def test_parse_semgrep_json(fixtures_dir):
    with open(os.path.join(fixtures_dir, "semgrep_sample.json"), encoding="utf-8") as fh:
        raw = json.load(fh)
    findings = sast.parse_semgrep_json(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id.endswith("jdbc-sqli")
    assert f.path.endswith("UserDao.java")
    assert f.start_line == 14
    assert f.severity.upper() == "ERROR"
    assert f.tool == "semgrep"


def test_parse_codeql_sarif(fixtures_dir):
    with open(os.path.join(fixtures_dir, "codeql_sample.sarif"), encoding="utf-8") as fh:
        sarif = json.load(fh)
    findings = sast.parse_codeql_sarif(sarif)
    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "java/sql-injection"
    assert f.path.endswith("UserDao.java")
    assert f.start_line == 14
    assert f.tool == "codeql"


def test_filter_by_cwe_unscoped_when_no_mapping():
    # An empty cwe returns findings unchanged.
    sf = sast.SastFindings(
        findings=[sast.Finding("x", "A.java", 1, 1, "ERROR", "m", "semgrep")],
        raw={},
    )
    out = sast.filter_by_cwe(sf, "", "config/cwe_focus.yaml")
    assert len(out.findings) == 1
