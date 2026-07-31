"""Backward-compatible `ossbomer-schema` command (N4).

Structural schema validation only, so unlike the other commands it does not run
the profile engine. Exit codes follow the same convention as `ossbomer validate`:
1 means the document is invalid, 2 means it could not be processed at all.
"""
import argparse
import sys

from ossbomer.core.schema_validation import validate_schema

EXIT_INVALID = 1
EXIT_ERROR = 2


def main():
    parser = argparse.ArgumentParser(
        description="Validate an SBOM (SPDX or CycloneDX, JSON or XML) against its schema."
    )
    parser.add_argument("file", type=str, help="Path to the SBOM file to validate.")
    parser.add_argument(
        "--format",
        choices=["spdx-json", "spdx-xml", "cyclonedx-json", "cyclonedx-xml"],
        default=None,
        help="Optional: assert an expected format/encoding. The version is always "
             "auto-detected from the document; omit to auto-detect everything.",
    )
    parser.add_argument("--json", action="store_true", help="Emit the result as JSON.")
    args = parser.parse_args()

    try:
        result = validate_schema(args.file)
    # An unreadable or undetectable document is a message and exit 2, not a
    # traceback. A validator that stack-traces at its users is a bad validator.
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(EXIT_ERROR)

    if args.format is not None:
        expected_format, expected_encoding = args.format.split("-")
        if (result.sbom_format, result.encoding) != (expected_format, expected_encoding):
            print(f"Format mismatch: detected {result.sbom_format}-{result.encoding}, "
                  f"expected {args.format}", file=sys.stderr)
            sys.exit(EXIT_ERROR)

    if args.json:
        import json
        print(json.dumps({
            "valid": result.valid,
            "format": result.sbom_format,
            "version": result.spec_version,
            "encoding": result.encoding,
            "partial": result.partial,
            "errors": result.errors,
        }, indent=2))
    else:
        print(result)

    sys.exit(0 if result.valid else EXIT_INVALID)


if __name__ == "__main__":
    main()
