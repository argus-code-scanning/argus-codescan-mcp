from __future__ import annotations

import argparse
import json
import sys

from argus_languages import __version__, scan_directory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="argus-languages",
        description="Built-in multi-language security pattern scanner (Java, PHP, Terraform, Ansible, …)",
    )
    parser.add_argument("--version", action="version", version=f"argus-languages {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan a file or directory")
    scan_p.add_argument("target", help="Path to scan")
    scan_p.add_argument(
        "--format", "-f", choices=["table", "json"], default="table", help="Output format"
    )

    args = parser.parse_args(argv)
    if args.command != "scan":
        return 2

    result = scan_directory(args.target)
    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        if result.errors:
            for err in result.errors:
                print(f"Note: {err}", file=sys.stderr)
        if not result.findings:
            print("No findings.")
        for f in result.findings:
            sev = f.severity.value.upper()
            loc = f"{f.file}:{f.line}" if f.file else "?"
            print(f"[{sev}] {loc} — {f.title} ({f.rule_id})")

    return 1 if result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
