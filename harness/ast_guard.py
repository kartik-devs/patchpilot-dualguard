"""Back-compat shim: re-exports the AST non-deletion guard.

The canonical implementation lives in :mod:`harness.layers.ast_guard`. This flat
module keeps the ``harness.ast_guard`` import path working (single source of truth,
no duplicated logic).
"""

from harness.layers.ast_guard import (  # noqa: F401
    NonDeletionResult,
    non_deletion_ok,
)
from harness.layers.ast_guard import _try_import_javalang  # noqa: F401

__all__ = ["NonDeletionResult", "non_deletion_ok"]
