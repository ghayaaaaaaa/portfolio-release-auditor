from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .audit import audit


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="portfolio-audit",
        description="Scan a local project for common public-release risks without printing matched values.",
    )
    parser.add_argument("project", type=Path, help="Directory to inspect.")
    parser.add_argument("--json-output", type=Path, help="Optional path for the safe JSON report.")
    args = parser.parse_args(argv)

    try:
        report = audit(args.project)
    except (OSError, ValueError) as exc:
        print(f"Could not complete the scan: {type(exc).__name__}", file=sys.stderr)
        return 2

    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Report saved: {args.json_output}")
    print(f"Status: {report['publication_status']}")
    print(f"Files seen: {report['counts']['files_seen']}")
    print(f"Text files scanned: {report['counts']['text_files_scanned']}")
    print(f"Findings: {report['counts']['findings']}")
    print(f"Blockers: {report['counts']['blockers']}")
    if not args.json_output:
        print(rendered)
    return 1 if report["counts"]["blockers"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

