from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

MAX_TEXT_BYTES = 2_000_000
LARGE_FILE_BYTES = 10_000_000

PRUNED_DIRS = {
    ".agent",
    ".git",
    ".local",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".dart_tool",
    "build",
    "dist",
    ".idea",
    ".vscode",
    ".ipynb_checkpoints",
    "data",
    "dataset",
    "datasets",
    "private",
    "records",
    "uploads",
    "outputs",
    "output",
    "runs",
    "weights",
    "checkpoints",
}

SENSITIVE_DIR_NAMES = {
    ".agent",
    ".local",
    "data",
    "dataset",
    "datasets",
    "private",
    "records",
    "uploads",
    "outputs",
    "output",
    "runs",
    "weights",
    "checkpoints",
}

TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".txt",
    ".key",
    ".pem",
    ".asc",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".env",
    ".html",
    ".ipynb",
    ".js",
    ".ts",
    ".dart",
    ".sh",
    ".ps1",
    ".xml",
    ".properties",
}

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private-key-marker",
        re.compile(
            r"-----BEGIN (?:PGP PRIVATE KEY BLOCK|"
            r"(?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----"
        ),
    ),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("generic-secret-assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|password)\b"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{12,}"
    )),
)

EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_PATTERN = re.compile(r"(?<!\w)(?:\+\d{1,3}[\s().-]?)?(?:\d[\s().-]?){8,14}(?!\w)")
LOCAL_USER_PATH_PATTERN = re.compile(
    "(?i)(?:[A-Z]:" + re.escape(chr(92)) + r"Users" + re.escape(chr(92))
    + r"|" + chr(47) + r"home" + chr(47) + r"[^/]+" + chr(47)
    + r"|" + chr(47) + r"Users" + chr(47) + r"[^/]+" + chr(47) + ")"
)

SENSITIVE_FILE_PATTERN = re.compile(
    r"(?i)(?:^|[._-])(?:secret|credential|password|token|private.?key|"
    r"resume|cv|patient|medical|health.?record|student.?record)(?:[._-]|$)"
)
PRIVATE_KEY_FILE_NAMES = {
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_xmss",
    "id_ecdsa_sk",
    "id_ed25519_sk",
    "ssh_host_rsa_key",
    "ssh_host_dsa_key",
    "ssh_host_ecdsa_key",
    "ssh_host_ed25519_key",
}
MODEL_SUFFIXES = {".pt", ".pth", ".h5", ".hdf5", ".keras", ".onnx", ".tflite", ".pkl", ".pickle"}
DATA_SUFFIXES = {".csv", ".tsv", ".parquet", ".feather", ".sqlite", ".sqlite3", ".db"}
OPAQUE_KEY_CONTAINER_SUFFIXES = {".pgp", ".gpg"}
ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar", ".tar", ".gz"}
LICENSE_NAMES = {"license", "license.md", "license.txt", "copying"}


def _is_sensitive_file_name(name: str) -> bool:
    file_name = name.lower()
    return bool(
        SENSITIVE_FILE_PATTERN.search(name)
        or file_name in PRIVATE_KEY_FILE_NAMES
        or file_name == ".env"
        or (file_name.startswith(".env.") and file_name != ".env.example")
    )


def _finding(category: str, path: str, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"category": category, "path": path}
    result.update(extra)
    return result


def _scan_text(path: Path, relative: str) -> tuple[list[dict[str, Any]], int]:
    findings: list[dict[str, Any]] = []
    if path.stat().st_size > MAX_TEXT_BYTES:
        return [_finding("text-file-too-large-skipped", relative)], 0

    if path.suffix.lower() == ".ipynb":
        try:
            notebook = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
            return [_finding("notebook-unreadable", relative)], 0
        if not isinstance(notebook, dict):
            return [_finding("notebook-unreadable", relative)], 0
        cells = notebook.get("cells")
        if not isinstance(cells, list) or any(not isinstance(cell, dict) for cell in cells):
            return [_finding("notebook-unreadable", relative)], 0
        output_count = 0
        sources: list[str] = []
        for cell in cells:
            outputs = cell.get("outputs", [])
            if "source" not in cell:
                return [_finding("notebook-unreadable", relative)], 0
            source = cell["source"]
            if not isinstance(outputs, list):
                return [_finding("notebook-unreadable", relative)], 0
            if isinstance(source, str):
                sources.append(source)
            elif isinstance(source, list) and all(isinstance(part, str) for part in source):
                sources.extend(source)
            else:
                return [_finding("notebook-unreadable", relative)], 0
            output_count += len(outputs)
        if output_count:
            findings.append(_finding("notebook-outputs-present", relative, output_count=output_count))
        lines = "\n".join(sources).splitlines()
    else:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return [_finding("text-file-unreadable", relative)], 0

    for line_number, line in enumerate(lines, 1):
        for category, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(_finding(category, relative, line=line_number))
        if EMAIL_PATTERN.search(line):
            findings.append(_finding("contact-like-email", relative, line=line_number))
        if PHONE_PATTERN.search(line):
            findings.append(_finding("contact-like-phone", relative, line=line_number))
        if LOCAL_USER_PATH_PATTERN.search(line):
            findings.append(_finding("local-user-path", relative, line=line_number))
    return findings, output_count if path.suffix.lower() == ".ipynb" else 0


def audit(root: Path) -> dict[str, Any]:
    root = root.expanduser()
    if any(part.lower() == ".git" for part in root.parts):
        raise ValueError("Scan the project root, not Git metadata.")
    root = root.resolve()
    if any(part.lower() == ".git" for part in root.parts):
        raise ValueError("Scan the project root, not Git metadata.")
    if not root.exists() or not root.is_dir():
        raise ValueError("The project path must be an existing directory.")

    findings: list[dict[str, Any]] = []
    counts = {"files_seen": 0, "text_files_scanned": 0, "directories_pruned": 0, "large_files": 0}
    license_found = False
    stack = [root]

    while stack:
        directory = stack.pop()
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name.lower())
        except OSError:
            findings.append(_finding("directory-unreadable", directory.relative_to(root).as_posix() or "."))
            continue

        for entry in entries:
            relative = entry.relative_to(root).as_posix()
            file_name = entry.name.lower()
            try:
                if entry.is_symlink():
                    findings.append(_finding("symlink-skipped", relative))
                    if file_name == ".git":
                        findings.append(_finding("git-history-not-scanned", relative))
                    elif file_name in SENSITIVE_DIR_NAMES:
                        findings.append(_finding("sensitive-data-directory-symlink", relative))
                    elif (
                        _is_sensitive_file_name(entry.name)
                        or entry.suffix.lower() in {".key", ".pem", ".asc", ".pgp", ".gpg"}
                    ):
                        findings.append(_finding("sensitive-file-symlink", relative))
                    continue
                if entry.is_dir():
                    relative_parts = entry.relative_to(root).parts[:-1]
                    source_layer_data = (
                        entry.name.lower() == "data"
                        and any(part.lower() in {"src", "lib"} for part in relative_parts)
                    )
                    if entry.name.lower() in PRUNED_DIRS and not source_layer_data:
                        counts["directories_pruned"] += 1
                        if entry.name.lower() == ".git":
                            findings.append(_finding("git-history-not-scanned", relative))
                        elif entry.name.lower() in SENSITIVE_DIR_NAMES:
                            findings.append(_finding("sensitive-data-directory-pruned", relative))
                        continue
                    stack.append(entry)
                    continue
                if not entry.is_file():
                    continue
                counts["files_seen"] += 1
                if file_name == ".git":
                    findings.append(_finding("git-history-not-scanned", relative))
                if _is_sensitive_file_name(entry.name):
                    findings.append(_finding("sensitive-filename", relative))
                if entry.parent == root and file_name in LICENSE_NAMES:
                    license_found = True

                suffix = entry.suffix.lower()
                size = entry.stat().st_size
                if suffix in MODEL_SUFFIXES:
                    findings.append(_finding("model-or-serialized-artifact", relative, bytes=size))
                    continue
                if suffix in DATA_SUFFIXES:
                    findings.append(_finding("data-file-excluded-from-content-scan", relative, bytes=size))
                    continue
                if suffix in OPAQUE_KEY_CONTAINER_SUFFIXES:
                    findings.append(_finding("encrypted-key-container-review", relative, bytes=size))
                    continue
                if suffix in ARCHIVE_SUFFIXES:
                    findings.append(_finding("archive-file", relative, bytes=size))
                    continue
                if size > LARGE_FILE_BYTES:
                    counts["large_files"] += 1
                    findings.append(_finding("large-file-review", relative, bytes=size))
                    continue
                if suffix in TEXT_SUFFIXES:
                    text_findings, _ = _scan_text(entry, relative)
                    counts["text_files_scanned"] += 1
                    findings.extend(text_findings)
            except OSError:
                findings.append(_finding("file-unreadable", relative))

    blockers = {
        "private-key-marker",
        "aws-access-key",
        "github-token",
        "generic-secret-assignment",
        "sensitive-filename",
        "model-or-serialized-artifact",
        "data-file-excluded-from-content-scan",
        "encrypted-key-container-review",
        "git-history-not-scanned",
        "sensitive-data-directory-pruned",
        "sensitive-data-directory-symlink",
        "sensitive-file-symlink",
    }
    blocker_count = sum(item["category"] in blockers for item in findings)
    return {
        "schema_version": 1,
        "publication_status": "blockers-found" if blocker_count else "manual-review-required",
        "counts": {
            **counts,
            "findings": len(findings),
            "blockers": blocker_count,
            "license_file_found": license_found,
        },
        "findings": findings,
        "disclaimer": (
            "A clean scan does not prove safety, authorship, or license rights. "
            "Review source, data, model, and third-party terms before release."
        ),
    }

