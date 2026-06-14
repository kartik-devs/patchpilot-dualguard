"""MG4: AST non-deletion guard deletion-detection tests."""

from __future__ import annotations

from harness.layers import ast_guard  # via the layer shim -> harness.ast_guard


_ORIGINAL = """
package demo;

public class UserDao {
    private final java.sql.Connection conn;
    public UserDao(java.sql.Connection c) { this.conn = c; }

    public String findByName(String name) throws Exception {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        java.sql.Statement st = conn.createStatement();
        if (name == null) { throw new IllegalArgumentException("null"); }
        return st.executeQuery(sql).toString();
    }
}
"""

_BENIGN_FIX = """
package demo;

public class UserDao {
    private final java.sql.Connection conn;
    public UserDao(java.sql.Connection c) { this.conn = c; }

    public String findByName(String name) throws Exception {
        if (name == null) { throw new IllegalArgumentException("null"); }
        java.sql.PreparedStatement ps = conn.prepareStatement(
            "SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        return ps.executeQuery().toString();
    }
}
"""

_DELETE_THE_SINK = """
package demo;

public class UserDao {
    public String findByName(String name) {
        return null;
    }
}
"""

_BROKEN = "package demo; public class UserDao { this won't parse ( ; }"


def test_identity_passes():
    r = ast_guard.non_deletion_ok(_ORIGINAL, _ORIGINAL, min_retained_ratio=0.6)
    assert r.ok is True
    assert r.retained_ratio >= 1.0


def test_benign_fix_passes():
    r = ast_guard.non_deletion_ok(_ORIGINAL, _BENIGN_FIX, min_retained_ratio=0.6)
    assert r.ok is True
    assert r.returns_kept is True


def test_delete_the_sink_rejected():
    r = ast_guard.non_deletion_ok(_ORIGINAL, _DELETE_THE_SINK, min_retained_ratio=0.6)
    assert r.ok is False
    # Either the statement ratio collapsed or a return/throw path was dropped.
    assert r.retained_ratio < 0.6 or r.returns_kept is False


def test_non_parseable_patch_rejected_on_ast_path():
    # Only assert the hard-reject when javalang is actually available; the
    # line-based fallback cannot detect a parse failure.
    if ast_guard._try_import_javalang() is None:  # pragma: no cover
        return
    r = ast_guard.non_deletion_ok(_ORIGINAL, _BROKEN, min_retained_ratio=0.6)
    assert r.ok is False


def test_counts_are_non_negative():
    r = ast_guard.non_deletion_ok(_ORIGINAL, _BENIGN_FIX)
    assert r.original_stmts >= 0
    assert r.patched_stmts >= 0
    assert r.original_returns >= 0
    assert r.patched_returns >= 0
