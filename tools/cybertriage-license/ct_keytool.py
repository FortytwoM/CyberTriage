#!/usr/bin/env python3
"""Convenience wrapper for the License4J 4.7.3 keypair/license tool.

Commands:
  build     compile the Java tool
  generate  create a keypair (RSA-2048 + secp112r1); optionally patch an
            MSI with the new public key and/or sign a license in the same run
  inspect   parse a License4J composite public key
  verify    batch-check .l4j license files in a folder
  sign      create a license from JSON/properties or re-sign an existing
            encrypted .l4j (single file or a whole folder)
  patch-msi replace the embedded public key in an existing Cyber Triage MSI

The wrapper contains no cryptography of its own: every operation is
delegated to the Java tool so the composite-key format, signature input
and PBE container stay in one implementation.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path

import msi_patcher

TOOL_DIR = Path(__file__).resolve().parent
BUILD_DIR = TOOL_DIR / "build"
SOURCE_DIR = TOOL_DIR / "src" / "main" / "java"
MAIN_CLASS = "com.cybertriage.tools.license4j.License4JKeyPairGenerator"
MAIN_CLASS_FILE = (
    BUILD_DIR
    / "com"
    / "cybertriage"
    / "tools"
    / "license4j"
    / "License4JKeyPairGenerator.class"
)

VALID_STATUSES = ("VALID", "INVALID", "UNSIGNED", "UNREADABLE", "ERROR")
STATUS_LINE = re.compile(r"^Status\s*:\s*([A-Z]+)\s*$", re.MULTILINE)


# ---------------------------------------------------------------------------
# Java tool discovery and build
# ---------------------------------------------------------------------------


def find_tool(name: str, explicit: str | None = None) -> str:
    """Find java/javac in PATH or JAVA_HOME."""
    if explicit:
        return explicit

    found = shutil.which(name)
    if found:
        return found

    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        executable = name + (".exe" if os.name == "nt" else "")
        candidate = Path(java_home) / "bin" / executable
        if candidate.is_file():
            return str(candidate)

    raise SystemExit(
        f"error: {name} not found. Install a JDK and/or set JAVA_HOME, "
        f"or pass --{name} <path>."
    )


def build(force: bool = False, javac: str | None = None, quiet: bool = False) -> None:
    sources = sorted(SOURCE_DIR.rglob("*.java"))
    if not sources:
        raise SystemExit(f"error: no Java sources found under {SOURCE_DIR}")

    if (
        not force
        and MAIN_CLASS_FILE.is_file()
        and all(source.stat().st_mtime <= MAIN_CLASS_FILE.stat().st_mtime for source in sources)
    ):
        return

    compiler = find_tool("javac", javac)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    command = [
        compiler,
        "-encoding",
        "UTF-8",
        "-d",
        str(BUILD_DIR),
        *[str(source) for source in sources],
    ]
    if not quiet:
        print(f"Building Java tool with {compiler} ...")
    subprocess.run(command, check=True)


def java_command(java: str | None) -> list[str]:
    return [find_tool("java", java), "-cp", str(BUILD_DIR), MAIN_CLASS]


def run_java(
    arguments: Iterable[str],
    java: str | None,
    *,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        java_command(java) + list(arguments),
        capture_output=capture,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def add_java_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--java", metavar="PATH", help="path to java")
    parser.add_argument("--javac", metavar="PATH", help="path to javac")


def add_license_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--license-id", metavar="ID", help="license id (field 'id')")
    parser.add_argument("--customer", metavar="NAME", help="customer company (field 'ucom')")
    parser.add_argument("--customer-name", metavar="NAME", help="customer name (field 'ufn')")
    parser.add_argument(
        "--license-property",
        metavar="KEY=VALUE",
        action="append",
        default=[],
        help="override any license property (repeatable)",
    )


def license_arguments(args: argparse.Namespace) -> list[str]:
    result: list[str] = []
    if args.license_id is not None:
        result += ["--license-id", args.license_id]
    if args.customer is not None:
        result += ["--customer", args.customer]
    if args.customer_name is not None:
        result += ["--customer-name", args.customer_name]
    for assignment in args.license_property:
        result += ["--license-property", assignment]
    return result


def field(text: str, label: str) -> str:
    match = re.search(rf"^{re.escape(label)}\s*:\s*(.*)$", text, re.MULTILINE)
    return match.group(1).strip() if match else ""


def looks_like_container(text: str) -> bool:
    normalized = text.lstrip("\ufeff").strip()
    if not normalized.startswith("#"):
        return False
    normalized = re.sub(r"/\*.*?\*/", "", normalized, flags=re.DOTALL)
    header_end = normalized.find(")")
    if header_end < 0:
        return False
    payload = re.sub(r"\s", "", normalized[header_end + 1 :])
    return bool(re.fullmatch(r"[0-9A-Fa-f]+", payload)) and len(payload) >= 32


def collect_files(path: Path, pattern: str, recursive: bool) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []
    iterator = path.rglob(pattern) if recursive else path.glob(pattern)
    return sorted(candidate for candidate in iterator if candidate.is_file())


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def command_build(args: argparse.Namespace) -> int:
    build(force=True, javac=args.javac)
    print(f"Build OK: {BUILD_DIR}")
    return 0


def command_generate(args: argparse.Namespace) -> int:
    if (args.license_data is None) != (args.license_output is None):
        print("error: --license-data and --license-output must be used together", file=sys.stderr)
        return 2
    if args.msi is None and args.msi_output is not None:
        print("error: --msi-output requires --msi", file=sys.stderr)
        return 2

    build(javac=args.javac)

    keypair_dir = Path(args.out).expanduser().resolve()
    arguments = ["--out", args.out]
    for name, value in (
        ("--name", args.name),
        ("--description", args.description),
        ("--product-id", args.product_id),
        ("--product-edition", args.product_edition),
        ("--product-version", args.product_version),
        ("--reuse-ec-public", args.reuse_ec_public),
        ("--reuse-ec-private", args.reuse_ec_private),
    ):
        if value is not None:
            arguments += [name, value]
    if args.force:
        arguments.append("--force")

    result = run_java(arguments, args.java)
    if result.returncode != 0:
        return result.returncode

    if args.msi is not None:
        msi = Path(args.msi).expanduser().resolve()
        if args.msi_output is None:
            msi_output = msi.with_name(msi.stem + "-patched" + msi.suffix)
        else:
            msi_output = Path(args.msi_output).expanduser().resolve()
        try:
            patched = msi_patcher.patch_msi(
                msi,
                msi_output,
                (keypair_dir / "publickey.txt").read_text(encoding="ascii"),
                strip_signature=not args.msi_keep_signature,
                keep_temp=args.msi_keep_temp,
            )
        except (msi_patcher.PatchError, OSError) as error:
            print(f"error: MSI patch failed: {error}", file=sys.stderr)
            return 2
        print(f"Patched MSI: {patched.output}")
        print(f"JARs: {', '.join(patched.patched_jars)}")

    if args.license_data is not None:
        sign_arguments = [
            "--sign-license",
            args.license_data,
            "--public-key",
            str(keypair_dir / "publickey.txt"),
            "--private-key",
            str(keypair_dir / "rsa-private.pem"),
            "--signed-output",
            args.license_output,
        ]
        sign_arguments += license_arguments(args)
        return run_java(sign_arguments, args.java).returncode

    return 0


def command_patch_msi(args: argparse.Namespace) -> int:
    public_key = Path(args.public_key).expanduser()
    if not public_key.is_file():
        print(f"error: public key not found: {public_key}", file=sys.stderr)
        return 2
    old_key = None
    if args.old_public_key is not None:
        old_path = Path(args.old_public_key).expanduser()
        if not old_path.is_file():
            print(f"error: old public key not found: {old_path}", file=sys.stderr)
            return 2
        old_key = old_path.read_text(encoding="ascii")

    try:
        result = msi_patcher.patch_msi(
            Path(args.msi).expanduser(),
            Path(args.out).expanduser(),
            public_key.read_text(encoding="ascii"),
            old_public_key=old_key,
            strip_signature=not args.keep_signature,
            keep_temp=args.keep_temp,
        )
    except (msi_patcher.PatchError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print(f"Patched MSI: {result.output}")
    print(f"JARs: {', '.join(result.patched_jars)}")
    if result.removed_signatures:
        print(f"Removed signature streams: {', '.join(result.removed_signatures)}")
    return 0


def command_inspect(args: argparse.Namespace) -> int:
    build(javac=args.javac)
    return run_java(["--inspect-public-key", args.public_key], args.java).returncode


def verify_one(
    path: Path,
    public_key: Path,
    args: argparse.Namespace,
) -> dict[str, str]:
    java_arguments = ["--verify-license", str(path), "--public-key", str(public_key)]
    if args.show_content or args.show_secrets:
        java_arguments.append("--show-license-content")
    if args.show_secrets:
        java_arguments.append("--show-secrets")

    completed = run_java(java_arguments, args.java, capture=True)
    output = (completed.stdout or "") + (completed.stderr or "")

    match = STATUS_LINE.search(output)
    if match is not None:
        status = match.group(1)
    elif completed.returncode == 2:
        status = "ERROR"
    else:
        try:
            status = "UNREADABLE" if looks_like_container(path.read_text(encoding="utf-8")) else "UNSIGNED"
        except (OSError, UnicodeError):
            status = "ERROR"

    reason = field(output, "Reason")
    if status == "ERROR" and not reason:
        reason = (completed.stderr or "").strip() or f"exit code {completed.returncode}"

    return {
        "file": str(path),
        "status": status,
        "licenseId": field(output, "License id"),
        "product": field(output, "Product"),
        "customer": field(output, "Customer"),
        "reason": reason,
        "output": output.strip(),
    }


def command_verify(args: argparse.Namespace) -> int:
    licenses = Path(args.licenses).expanduser()
    public_key = Path(args.public_key).expanduser()
    if not licenses.exists():
        print(f"error: license path not found: {licenses}", file=sys.stderr)
        return 2
    if not public_key.is_file():
        print(f"error: public key not found: {public_key}", file=sys.stderr)
        return 2

    files = collect_files(licenses, args.pattern, args.recursive)
    if not files:
        print(f"error: no files matching {args.pattern!r} under {licenses}", file=sys.stderr)
        return 2

    build(javac=args.javac)

    results = [verify_one(path, public_key, args) for path in files]

    for result in results:
        line = f"{result['status']:<10} {result['file']}"
        if result["licenseId"]:
            line += f"  id={result['licenseId']}"
        print(line)
        if result["status"] != "VALID" and result["reason"]:
            print(f"           {result['reason']}")
        if args.show_content and result["output"]:
            print("\n".join(f"           {row}" for row in result["output"].splitlines()))
            print()

    if args.json:
        report = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "publicKey": str(public_key),
            "results": [
                {key: value for key, value in result.items() if key != "output"}
                for result in results
            ],
        }
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"JSON report: {args.json}")
    if args.csv:
        Path(args.csv).parent.mkdir(parents=True, exist_ok=True)
        with Path(args.csv).open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["file", "status", "licenseId", "product", "customer", "reason"],
            )
            writer.writeheader()
            for result in results:
                writer.writerow({key: value for key, value in result.items() if key != "output"})
        print(f"CSV report : {args.csv}")

    return 0 if all(result["status"] == "VALID" for result in results) else 1


def sign_one(
    source: Path,
    target: Path,
    args: argparse.Namespace,
) -> tuple[bool, str]:
    if target.exists():
        return False, f"output already exists: {target}"
    target.parent.mkdir(parents=True, exist_ok=True)

    java_arguments = [
        "--sign-license",
        str(source),
        "--public-key",
        args.public_key,
        "--private-key",
        args.private_key,
        "--signed-output",
        str(target),
    ]
    java_arguments += license_arguments(args)

    completed = run_java(java_arguments, args.java, capture=True)
    message = ((completed.stdout or "") + (completed.stderr or "")).strip()
    return completed.returncode == 0, message


def command_sign(args: argparse.Namespace) -> int:
    source = Path(args.license).expanduser()
    target = Path(args.out).expanduser()
    public_key = Path(args.public_key).expanduser()
    private_key = Path(args.private_key).expanduser()

    if not source.exists():
        print(f"error: input not found: {source}", file=sys.stderr)
        return 2
    if not public_key.is_file():
        print(f"error: public key not found: {public_key}", file=sys.stderr)
        return 2
    if not private_key.is_file():
        print(f"error: private key not found: {private_key}", file=sys.stderr)
        return 2

    files = collect_files(source, args.pattern, args.recursive)
    if not files:
        print(f"error: no files matching {args.pattern!r} under {source}", file=sys.stderr)
        return 2

    build(javac=args.javac)
    args.public_key = str(public_key)
    args.private_key = str(private_key)

    if source.is_dir():
        target.mkdir(parents=True, exist_ok=True)
        pairs = [(path, target / path.name) for path in files]
    else:
        if len(files) != 1:
            print("error: expected exactly one input file", file=sys.stderr)
            return 2
        if target.is_dir():
            print(f"error: --out must be a file for a single input: {target}", file=sys.stderr)
            return 2
        pairs = [(files[0], target)]

    failed = 0
    for origin, destination in pairs:
        ok, message = sign_one(origin, destination, args)
        if ok:
            print(f"SIGNED {origin} -> {destination}")
        else:
            failed += 1
            print(f"ERROR  {origin}: {message}", file=sys.stderr)

    return 0 if failed == 0 else 1


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ct_keytool.py",
        description="License4J 4.7.3 keypair and Cyber Triage license tool",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser_ = subparsers.add_parser("build", help="compile the Java tool")
    build_parser_.add_argument("--javac", metavar="PATH", help="path to javac")
    build_parser_.set_defaults(func=command_build)

    generate = subparsers.add_parser(
        "generate",
        help="generate a keypair; optionally patch an MSI and/or sign a license",
    )
    generate.add_argument("--out", required=True, help="keypair output directory")
    generate.add_argument("--name", default="Cyber Triage", help="keypair name")
    generate.add_argument("--description", default="", help="keypair description")
    generate.add_argument("--product-id", default="Cyber Triage", help="product id metadata")
    generate.add_argument("--product-edition", default="", help="product edition metadata")
    generate.add_argument("--product-version", default="", help="product version metadata")
    generate.add_argument("--reuse-ec-public", metavar="FILE", help="reuse an EC public key")
    generate.add_argument("--reuse-ec-private", metavar="FILE", help="reuse an EC private key")
    generate.add_argument(
        "--force",
        action="store_true",
        help="overwrite a non-empty keypair output directory",
    )
    generate.add_argument(
        "--license-data",
        metavar="FILE",
        help="JSON extended data or properties; creates and signs a license",
    )
    generate.add_argument(
        "--license-output",
        metavar="FILE",
        help="signed .l4j output (used with --license-data)",
    )
    generate.add_argument(
        "--msi",
        metavar="FILE",
        help="Cyber Triage MSI to patch with the generated public key",
    )
    generate.add_argument(
        "--msi-output",
        metavar="FILE",
        help="patched MSI output (default: <msi>-patched.msi)",
    )
    generate.add_argument(
        "--msi-keep-signature",
        action="store_true",
        help="do not remove the invalid Authenticode signature streams",
    )
    generate.add_argument(
        "--msi-keep-temp",
        action="store_true",
        help="keep the temporary MSI extraction directory",
    )
    add_license_options(generate)
    add_java_options(generate)
    generate.set_defaults(func=command_generate)

    inspect = subparsers.add_parser("inspect", help="parse a composite public key")
    inspect.add_argument("--public-key", required=True, metavar="FILE")
    add_java_options(inspect)
    inspect.set_defaults(func=command_inspect)

    verify = subparsers.add_parser("verify", help="batch-check license files")
    verify.add_argument("--public-key", required=True, metavar="FILE")
    verify.add_argument(
        "--licenses",
        required=True,
        metavar="PATH",
        help="license file or directory",
    )
    verify.add_argument("--pattern", default="*.l4j", help="glob pattern (default: *.l4j)")
    verify.add_argument("--recursive", action="store_true", help="search subdirectories")
    verify.add_argument("--json", metavar="FILE", help="write a JSON report")
    verify.add_argument("--csv", metavar="FILE", help="write a CSV report")
    verify.add_argument(
        "--show-content",
        action="store_true",
        help="print decrypted properties (secrets masked)",
    )
    verify.add_argument(
        "--show-secrets",
        action="store_true",
        help="do not mask api_key/password/token values",
    )
    add_java_options(verify)
    verify.set_defaults(func=command_verify)

    sign = subparsers.add_parser(
        "sign",
        help="create a license from JSON/properties or re-sign an encrypted .l4j",
    )
    sign.add_argument("--license", required=True, metavar="PATH", help="input file or folder")
    sign.add_argument("--public-key", required=True, metavar="FILE")
    sign.add_argument("--private-key", required=True, metavar="FILE")
    sign.add_argument("--out", required=True, metavar="PATH", help="output file or folder")
    sign.add_argument("--pattern", default="*.l4j", help="glob pattern for folders")
    sign.add_argument("--recursive", action="store_true", help="search subdirectories")
    add_license_options(sign)
    add_java_options(sign)
    sign.set_defaults(func=command_sign)

    patch_msi = subparsers.add_parser(
        "patch-msi",
        help="replace the embedded public key in an existing Cyber Triage MSI",
    )
    patch_msi.add_argument("--msi", required=True, metavar="FILE", help="source MSI")
    patch_msi.add_argument("--out", required=True, metavar="FILE", help="patched MSI output")
    patch_msi.add_argument(
        "--public-key", required=True, metavar="FILE", help="new composite public key"
    )
    patch_msi.add_argument(
        "--old-public-key", metavar="FILE", help="old composite public key (optional)"
    )
    patch_msi.add_argument(
        "--keep-signature",
        action="store_true",
        help="do not remove the invalid Authenticode signature streams",
    )
    patch_msi.add_argument(
        "--keep-temp", action="store_true", help="keep the temporary extraction directory"
    )
    patch_msi.set_defaults(func=command_patch_msi)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except subprocess.CalledProcessError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
