import argparse
import json
import sys
from pathlib import Path

from leakshield_core import SUPPORTED_EXTENSIONS, scan_path


RISK_ORDER = {"Low": 0, "Medium": 1, "High": 2}


def build_parser():
    parser = argparse.ArgumentParser(
        prog="leakshield",
        description="Scan files for PII, financial data, credentials, and generate redacted copies.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan one or more files.")
    scan.add_argument("files", nargs="+", type=Path, help="Files to scan.")
    scan.add_argument(
        "--redact-dir",
        type=Path,
        help="Write redacted text copies into this directory.",
    )
    scan.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of human-readable output.",
    )
    scan.add_argument(
        "--fail-on-risk",
        choices=["Low", "Medium", "High"],
        help="Exit with code 2 when a scanned file is at or above this risk level.",
    )

    return parser


def write_redacted_copy(result, output_dir):
    source = Path(result["file"])
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"redacted_{source.stem}.txt"
    output_path.write_text(result["redacted"])
    return output_path


def print_human_result(result, redacted_path=None):
    print(f"\n{result['file']}")
    print(f"Risk Level: {result['risk']} ({result['score']}/100)")

    print("Why is this risky?")
    for reason in result["reasons"] or ["No sensitive data detected"]:
        print(f"- {reason}")

    print("Recommended Actions:")
    for recommendation in result["recommendations"]:
        print(f"- {recommendation}")

    if redacted_path:
        print(f"Redacted copy: {redacted_path}")


def scan_files(args):
    results = []
    exit_code = 0

    for file_path in args.files:
        if not file_path.exists():
            print(f"leakshield: file not found: {file_path}", file=sys.stderr)
            exit_code = 1
            continue

        if file_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            supported = ", ".join(sorted(SUPPORTED_EXTENSIONS))
            print(
                f"leakshield: unsupported file type for {file_path} "
                f"(supported: {supported})",
                file=sys.stderr,
            )
            exit_code = 1
            continue

        try:
            result = scan_path(file_path)
        except Exception as exc:
            print(f"leakshield: failed to scan {file_path}: {exc}", file=sys.stderr)
            exit_code = 1
            continue

        redacted_path = None
        if args.redact_dir:
            redacted_path = write_redacted_copy(result, args.redact_dir)
            result["redacted_file"] = str(redacted_path)

        results.append(result)

        if args.fail_on_risk and RISK_ORDER[result["risk"]] >= RISK_ORDER[args.fail_on_risk]:
            exit_code = 2

        if not args.json:
            print_human_result(result, redacted_path)

    if args.json:
        print(json.dumps(results, indent=2))

    return exit_code


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return scan_files(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
