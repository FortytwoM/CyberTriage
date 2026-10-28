#!/usr/bin/env python3
"""One-command pipeline for Cyber Triage keypair, MSI patch and licenses.

Typical use:
    python tools/cybertriage-license/issue.py

The MSI is picked up from ``input/``; results are written to ``output/``:
    output/keypair/                       RSA + EC keys and public key
    output/<name>-patched.msi             MSI with the new public key
    output/licenses/CLIENT.l4j            signed typical licenses
    output/licenses/SERVER.l4j
    output/licenses/STANDALONE.l4j
    output/report.json / report.txt

All heavy lifting stays in ``ct_keytool.py`` (Java wrapper) and
``msi_patcher.py`` (MSI/JAR/CAB patch). This module only orchestrates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

import ct_keytool
import msi_patcher

TOOL_DIR = Path(__file__).resolve().parent
ROOT = TOOL_DIR.parents[1]
STATUS_LINE = re.compile(r"^Status\s*:\s*([A-Z]+)\s*$", re.MULTILINE)


class IssueError(RuntimeError):
    pass


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def env_text(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def log(message: str) -> None:
    print(f"[issue] {message}", flush=True)


def find_msi(input_dir: Path, explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise IssueError(f"MSI not found: {path}")
        return path

    if not input_dir.is_dir():
        raise IssueError(f"input directory not found: {input_dir}")
    candidates = sorted(
        {
            path.resolve()
            for path in list(input_dir.glob("*.msi")) + list(input_dir.glob("*.MSI"))
            if path.is_file()
        }
    )
    if not candidates:
        raise IssueError(
            f"no MSI found in {input_dir}; put exactly one .msi there "
            "or pass --msi <file>"
        )
    if len(candidates) > 1:
        names = ", ".join(path.name for path in candidates)
        raise IssueError(
            f"multiple MSIs found in {input_dir}: {names}; "
            "keep one or pass --msi <file>"
        )
    return candidates[0]


def normalize_key(text: str) -> str:
    return re.sub(r"\s", "", text)


def key_sha256(public_key: str) -> str:
    return hashlib.sha256(normalize_key(public_key).encode("ascii")).hexdigest()


def ensure_keypair(
    keypair_dir: Path,
    *,
    new_keypair: bool,
    java: str | None,
    javac: str | None,
) -> tuple[Path, Path]:
    public_key = keypair_dir / "publickey.txt"
    private_key = keypair_dir / "rsa-private.pem"
    ready = public_key.is_file() and private_key.is_file()

    if new_keypair:
        if ready or (keypair_dir.exists() and any(keypair_dir.iterdir())):
            log(f"Removing existing keypair: {keypair_dir}")
            shutil.rmtree(keypair_dir)
        ready = False

    if ready:
        log(f"Reusing keypair: {keypair_dir}")
        return public_key, private_key

    if keypair_dir.exists() and any(keypair_dir.iterdir()):
        raise IssueError(
            f"incomplete keypair directory: {keypair_dir}; "
            "remove it or pass --new-keypair"
        )

    log("Generating keypair")
    ct_keytool.build(javac=javac)
    result = ct_keytool.run_java(["--out", str(keypair_dir)], java)
    if result.returncode != 0:
        raise IssueError("keypair generation failed")
    if not (public_key.is_file() and private_key.is_file()):
        raise IssueError(f"keypair files are missing in {keypair_dir}")
    return public_key, private_key


def existing_outputs(
    patched_msi: Path | None,
    license_outputs: list[Path],
    report_json: Path,
    report_txt: Path,
) -> list[Path]:
    paths = [path for path in license_outputs if path.exists()]
    if patched_msi is not None and patched_msi.exists():
        paths.append(patched_msi)
    for report in (report_json, report_txt):
        if report.exists():
            paths.append(report)
    return paths


def sign_license(
    source: Path,
    target: Path,
    public_key: Path,
    private_key: Path,
    args: argparse.Namespace,
) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    java_args = [
        "--sign-license",
        str(source),
        "--public-key",
        str(public_key),
        "--private-key",
        str(private_key),
        "--signed-output",
        str(target),
    ]
    if args.license_id:
        java_args += ["--license-id", args.license_id]
    if args.customer:
        java_args += ["--customer", args.customer]
    if args.customer_name:
        java_args += ["--customer-name", args.customer_name]
    for assignment in args.license_property:
        java_args += ["--license-property", assignment]

    result = ct_keytool.run_java(java_args, args.java)
    if result.returncode != 0:
        raise IssueError(f"signing failed: {source}")


def verify_license(path: Path, public_key: Path, java: str | None) -> tuple[str, str]:
    result = ct_keytool.run_java(
        ["--verify-license", str(path), "--public-key", str(public_key)],
        java,
        capture=True,
    )
    output = (result.stdout or "") + (result.stderr or "")
    match = STATUS_LINE.search(output)
    if match is not None:
        return match.group(1), output
    if result.returncode == 2:
        return "ERROR", output
    return "UNKNOWN", output


def write_reports(
    report_json: Path,
    report_txt: Path,
    *,
    msi_source: Path | None,
    msi_patched: Path | None,
    keypair_dir: Path,
    public_key: Path,
    public_sha: str,
    licenses: list[dict[str, str]],
    removed_signatures: list[str],
) -> None:
    report = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "msi": {
            "source": str(msi_source) if msi_source else None,
            "patched": str(msi_patched) if msi_patched else None,
        },
        "keypair": {
            "directory": str(keypair_dir),
            "publicKey": str(public_key),
            "publicKeySha256": public_sha,
        },
        "licenses": licenses,
        "removedSignatureStreams": removed_signatures,
    }
    report_json.parent.mkdir(parents=True, exist_ok=True)
    report_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    lines = [
        "Cyber Triage license issue report",
        "=================================",
        f"Generated: {report['generated']}",
        "",
        f"MSI source : {msi_source or '(not patched)'}",
        f"MSI patched: {msi_patched or '(not patched)'}",
        "",
        f"Keypair    : {keypair_dir}",
        f"Public key : {public_key}",
        f"Public key SHA-256: {public_sha}",
        "",
        "Licenses:",
    ]
    for item in licenses:
        lines.append(
            f"  {item['status']:<8} {item['output']}  id={item.get('licenseId', '')}"
        )
    if removed_signatures:
        lines += ["", "Removed MSI signature streams: " + ", ".join(removed_signatures)]
    lines += [
        "",
        "WARNING",
        "  Keep rsa-private.pem and ec-private.pem offline.",
        "  Install the application from the patched MSI; an already installed",
        "  copy still contains the old public key.",
    ]
    report_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(args: argparse.Namespace) -> int:
    input_dir = Path(args.input_dir).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    licenses_dir = Path(args.licenses_dir).expanduser().resolve()
    keypair_dir = output_dir / "keypair"
    licenses_out_dir = output_dir / "licenses"
    report_json = output_dir / "report.json"
    report_txt = output_dir / "report.txt"

    if not licenses_dir.is_dir():
        raise IssueError(f"licenses directory not found: {licenses_dir}")
    sources = sorted(path for path in licenses_dir.glob("*.l4j") if path.is_file())
    if not sources:
        raise IssueError(f"no *.l4j sources found in {licenses_dir}")

    msi = None if args.skip_msi else find_msi(input_dir, args.msi)
    patched_msi = (
        output_dir / (msi.stem + "-patched.msi") if msi is not None else None
    )
    license_outputs = [licenses_out_dir / path.name for path in sources]

    if args.new_keypair and not args.force:
        # A new key invalidates any previously issued artifacts.
        conflicts = existing_outputs(patched_msi, license_outputs, report_json, report_txt)
        if conflicts:
            raise IssueError(
                "--new-keypair would replace the key for existing outputs; "
                "pass --force or remove them first"
            )

    conflicts = existing_outputs(patched_msi, license_outputs, report_json, report_txt)
    if conflicts and not args.force:
        listed = ", ".join(str(path) for path in conflicts)
        raise IssueError(f"output already exists (use --force): {listed}")

    ct_keytool.build(javac=args.javac)
    output_dir.mkdir(parents=True, exist_ok=True)
    public_key, private_key = ensure_keypair(
        keypair_dir,
        new_keypair=args.new_keypair,
        java=args.java,
        javac=args.javac,
    )
    public_text = public_key.read_text(encoding="ascii")
    public_sha = key_sha256(public_text)

    removed_signatures: list[str] = []
    if msi is not None and patched_msi is not None:
        if patched_msi.exists():
            patched_msi.unlink()
        log(f"Patching MSI: {msi.name}")
        patch_result = msi_patcher.patch_msi(
            msi,
            patched_msi,
            public_text,
            strip_signature=not args.keep_signature,
            keep_temp=args.keep_temp,
        )
        removed_signatures = patch_result.removed_signatures
        log(f"Patched MSI: {patched_msi}")

    licenses_out_dir.mkdir(parents=True, exist_ok=True)
    signed: list[dict[str, str]] = []
    for source in sources:
        target = licenses_out_dir / source.name
        if target.exists():
            target.unlink()
        log(f"Signing {source.name}")
        sign_license(source, target, public_key, private_key, args)
        status, output = verify_license(target, public_key, args.java)
        if status != "VALID":
            print(output, file=sys.stderr)
            raise IssueError(f"verification failed for {target}: {status}")
        license_id = ct_keytool.field(output, "License id")
        signed.append(
            {
                "source": str(source),
                "output": str(target),
                "status": status,
                "licenseId": license_id,
            }
        )

    write_reports(
        report_json,
        report_txt,
        msi_source=msi,
        msi_patched=patched_msi,
        keypair_dir=keypair_dir,
        public_key=public_key,
        public_sha=public_sha,
        licenses=signed,
        removed_signatures=removed_signatures,
    )

    print()
    print("Done.")
    print(f"  Keypair      : {keypair_dir}")
    print(f"  Public key   : {public_key}")
    print(f"  Public SHA256: {public_sha}")
    if patched_msi is not None:
        print(f"  Patched MSI  : {patched_msi}")
    print(f"  Licenses     : {licenses_out_dir}")
    print(f"  Report       : {report_txt}")
    print()
    print("Embed the public key into the application by installing from the")
    print("patched MSI. Keep the private keys offline.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="issue.py",
        description="One command: keypair + MSI patch + typical licenses",
    )
    parser.add_argument(
        "--input-dir",
        default=env_text("INPUT_DIR") or str(ROOT / "input"),
        help="directory containing exactly one .msi (default: input/)",
    )
    parser.add_argument(
        "--output-dir",
        default=env_text("OUTPUT_DIR") or str(ROOT / "output"),
        help="output directory (default: output/)",
    )
    parser.add_argument(
        "--licenses-dir",
        default=env_text("LICENSES_DIR") or str(ROOT / "licenses"),
        help="directory with typical .l4j extended data (default: licenses/)",
    )
    parser.add_argument("--msi", default=env_text("MSI"), help="explicit MSI path")
    parser.add_argument(
        "--license-id",
        default=env_text("LICENSE_ID") or "862145687",
        help="license id (default: 862145687; empty to omit)",
    )
    parser.add_argument("--customer", default=env_text("CUSTOMER"), help="ucom")
    parser.add_argument("--customer-name", default=env_text("CUSTOMER_NAME"), help="ufn")
    parser.add_argument(
        "--license-property",
        metavar="KEY=VALUE",
        action="append",
        default=[],
        help="extra license property (repeatable)",
    )
    parser.add_argument(
        "--skip-msi",
        action="store_true",
        default=env_bool("SKIP_MSI"),
        help="generate keypair and licenses only (no MSI patch)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        default=env_bool("FORCE"),
        help="overwrite existing patched MSI, licenses and report",
    )
    parser.add_argument(
        "--new-keypair",
        action="store_true",
        default=env_bool("NEW_KEYPAIR"),
        help="generate a new keypair instead of reusing output/keypair",
    )
    parser.add_argument(
        "--keep-signature",
        action="store_true",
        default=env_bool("KEEP_SIGNATURE"),
        help="do not remove invalid MSI signature streams",
    )
    parser.add_argument("--keep-temp", action="store_true", help="keep MSI temp files")
    parser.add_argument("--java", help="path to java")
    parser.add_argument("--javac", help="path to javac")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.license_id == "":
        args.license_id = None
    try:
        return run(args)
    except (IssueError, msi_patcher.PatchError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as error:  # pragma: no cover
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
