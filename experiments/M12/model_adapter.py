"""Explicit local-model availability gate for M12.

No fallback response is generated.  Callers must discover and verify a local
model themselves before using any semantic explanation path.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LocalModelAvailability:
    status: str
    executable: str | None
    reason: str


def inspect_local_model(executable: str | None) -> LocalModelAvailability:
    if not executable:
        return LocalModelAvailability("blocked", None, "No local model executable was configured.")
    path = Path(executable)
    if not path.is_file():
        return LocalModelAvailability("blocked", str(path), "Configured local model executable does not exist.")
    return LocalModelAvailability("available_but_not_invoked", str(path), "Invocation requires a bounded semantic validator.")
