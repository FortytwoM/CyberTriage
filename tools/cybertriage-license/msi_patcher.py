"""Patch the License4J public key inside a Cyber Triage MSI.

The MSI embeds ``disk1.cab``, which contains ``cybertriage4.0.0.jar`` and
``License4JLicense.class``.  Only the composite public-key string in that class
is replaced; everything else (including all other files) is preserved.

Pipeline:
  1. copy the MSI to the output path;
  2. extract the embedded cabinet(s) from the copy;
  3. patch ``License4JLicense.class`` inside the application JAR(s);
  4. rebuild the cabinet(s) with ``makecab``;
  5. replace the cabinet stream(s) and update the JAR size in the File table;
  6. remove the now-invalid Authenticode signature streams.

The replacement string has the same byte length as the original (the composite
key is always 743 characters and is wrapped at 60 characters), so the class
constant-pool entry can be patched in place without rewriting the class.
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

CLASS_NAME = "com/basistech/df/cybertriage/license/License4JLicense.class"
COMPOSITE_LENGTH = 743
WRAP_WIDTH = 60
SIGNATURE_STREAMS = ("\x05DigitalSignature", "\x05MsiDigitalSignatureEx")


class PatchError(RuntimeError):
    pass


@dataclass
class PatchResult:
    output: Path
    old_public_key: str
    new_public_key: str
    patched_jars: list[str] = field(default_factory=list)
    removed_signatures: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Class-file constant pool
# ---------------------------------------------------------------------------


def normalize_composite(value: str) -> str:
    return re.sub(r"\s", "", value)


def wrap_composite(value: str, width: int = WRAP_WIDTH) -> str:
    value = normalize_composite(value)
    return "\n".join(value[i : i + width] for i in range(0, len(value), width))


def _wrap_to_length(value: str, total: int) -> str:
    """Wrap ``value`` so that the result (with newlines) is exactly ``total`` chars."""
    value = normalize_composite(value)
    newlines = total - len(value)
    if newlines < 0:
        raise PatchError(
            f"new public key ({len(value)} chars) does not fit into the class slot ({total})"
        )
    lines = newlines + 1
    base, remainder = divmod(len(value), lines)
    parts = []
    offset = 0
    for index in range(lines):
        size = base + (1 if index < remainder else 0)
        parts.append(value[offset : offset + size])
        offset += size
    result = "\n".join(parts)
    if len(result) != total:
        raise PatchError("internal error while wrapping the public key")
    return result


def utf8_constants(data: bytes):
    """Yield ``(index, raw_offset, length, raw)`` for all CONSTANT_Utf8 entries."""
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        raise PatchError("not a Java class file")
    position = 8
    count = struct.unpack_from(">H", data, position)[0]
    position += 2
    index = 1
    while index < count:
        tag = data[position]
        position += 1
        if tag == 1:
            length = struct.unpack_from(">H", data, position)[0]
            offset = position + 2
            raw = data[offset : offset + length]
            yield index, offset, length, raw
            position = offset + length
        elif tag in (7, 8, 16, 19, 20):
            position += 2
        elif tag == 15:
            position += 3
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
            position += 4
        elif tag in (5, 6):
            position += 8
            index += 1
        else:
            raise PatchError(f"unsupported constant-pool tag {tag}")
        index += 1


def class_public_keys(data: bytes) -> list[str]:
    keys = []
    for _, _, _, raw in utf8_constants(data):
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        normalized = normalize_composite(value)
        if (
            len(normalized) == COMPOSITE_LENGTH
            and "SHA512withRSA" in normalized
            and "SHA512withECDSA" in normalized
        ):
            keys.append(normalized)
    return keys


def patch_class(
    data: bytes,
    new_public_key: str,
    old_public_key: str | None = None,
) -> tuple[bytes, str]:
    new_key = normalize_composite(new_public_key)
    if len(new_key) != COMPOSITE_LENGTH:
        raise PatchError(
            f"new public key must be {COMPOSITE_LENGTH} chars, got {len(new_key)}"
        )
    old_key = normalize_composite(old_public_key) if old_public_key else None

    matches = []
    for index, offset, length, raw in utf8_constants(data):
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        normalized = normalize_composite(value)
        if old_key is not None:
            if normalized == old_key:
                matches.append((index, offset, length))
        elif (
            len(normalized) == COMPOSITE_LENGTH
            and "SHA512withRSA" in normalized
            and "SHA512withECDSA" in normalized
        ):
            matches.append((index, offset, length))

    if len(matches) != 1:
        raise PatchError(
            f"expected exactly one public-key constant in the class, found {len(matches)}"
        )

    index, offset, length = matches[0]
    wrapped = _wrap_to_length(new_key, length).encode("ascii")
    patched = bytearray(data)
    patched[offset : offset + length] = wrapped
    patched = bytes(patched)

    if class_public_keys(patched) != [new_key]:
        raise PatchError("class verification failed after patching the public key")
    return patched, old_key or normalize_composite(
        data[offset : offset + length].decode("utf-8")
    )


# ---------------------------------------------------------------------------
# JAR / ZIP rewriting
# ---------------------------------------------------------------------------


def patch_jar(
    source: Path,
    destination: Path,
    new_public_key: str,
    old_public_key: str | None = None,
) -> tuple[str, str]:
    """Patch the class inside ``source`` and write ``destination``.

    Every other entry is copied with the same data; only the class entry is
    rewritten.  The JAR must not be signed with a non-empty signature block.
    """
    with zipfile.ZipFile(source) as zin:
        names = zin.namelist()
        if CLASS_NAME not in names:
            raise PatchError(f"{CLASS_NAME} not found in {source.name}")
        signatures = [
            name
            for name in names
            if name.upper().startswith("META-INF/")
            and name.upper().endswith((".RSA", ".DSA", ".EC"))
        ]
        if signatures:
            raise PatchError(
                "JAR is signed; patching it would invalidate the signature "
                f"({', '.join(signatures)})"
            )

        class_data = zin.read(CLASS_NAME)
        patched_class, old_key = patch_class(class_data, new_public_key, old_public_key)

        with zipfile.ZipFile(
            destination, "w", zipfile.ZIP_DEFLATED, allowZip64=True
        ) as zout:
            for info in zin.infolist():
                data = patched_class if info.filename == CLASS_NAME else zin.read(info)
                new_info = zipfile.ZipInfo(info.filename, info.date_time)
                new_info.compress_type = info.compress_type
                new_info.external_attr = info.external_attr
                new_info.internal_attr = info.internal_attr
                new_info.create_system = info.create_system
                new_info.comment = info.comment
                new_info.extra = info.extra
                zout.writestr(new_info, data)

    with zipfile.ZipFile(destination) as check:
        if check.testzip() is not None:
            raise PatchError(f"patched JAR is corrupt: {destination}")
        if class_public_keys(check.read(CLASS_NAME)) != [
            normalize_composite(new_public_key)
        ]:
            raise PatchError(f"patched JAR does not contain the new key: {destination}")

    return old_key, normalize_composite(new_public_key)


# ---------------------------------------------------------------------------
# External tools and MSI tables
# ---------------------------------------------------------------------------


def find_7z() -> str:
    candidates = [
        shutil.which("7z"),
        shutil.which("7zz"),
        shutil.which("7za"),
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise PatchError(
        "7-Zip not found; install 7-Zip (Windows) or p7zip-full (Linux) "
        "or add 7z/7zz to PATH"
    )


def find_gcab() -> str:
    found = shutil.which("gcab")
    if found:
        return found
    raise PatchError("gcab not found; install the 'gcab' package")


def find_msibuild() -> str:
    found = shutil.which("msibuild")
    if found:
        return found
    raise PatchError("msibuild not found; install the 'msitools' package")


def find_msiinfo() -> str:
    found = shutil.which("msiinfo")
    if found:
        return found
    raise PatchError("msiinfo not found; install the 'msitools' package")


def find_makecab() -> str:
    found = shutil.which("makecab")
    if found:
        return found
    windows = Path(r"C:\Windows\System32\makecab.exe")
    if windows.is_file():
        return str(windows)
    raise PatchError("makecab.exe not found")


def detect_backend() -> str:
    """Return 'windows' or 'linux' for the available MSI backend."""
    if os.name == "nt":
        try:
            import _msi  # noqa: F401
        except ImportError:
            pass
        else:
            if shutil.which("makecab") or Path(r"C:\Windows\System32\makecab.exe").is_file():
                return "windows"
    if shutil.which("msibuild") and shutil.which("msiinfo") and shutil.which("gcab"):
        return "linux"
    raise PatchError(
        "No MSI backend available. On Windows install Python 3.10-3.12 with "
        "_msi + makecab; on Linux install msitools + gcab."
    )


def _sql_escape(value: str) -> str:
    return value.replace("'", "''")


def _export_table(msiinfo: str, msi: Path, table: str) -> list[dict[str, str]]:
    result = subprocess.run(
        [msiinfo, "export", str(msi), table],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        raise PatchError(
            f"msiinfo export {table} failed: {(result.stderr or result.stdout).strip()}"
        )
    lines = result.stdout.splitlines()
    if len(lines) < 4:
        return []
    header = lines[0].split("\t")
    rows = []
    for line in lines[3:]:
        if not line.strip():
            continue
        values = line.split("\t")
        if len(values) < len(header):
            values += [""] * (len(header) - len(values))
        rows.append(dict(zip(header, values)))
    return rows


def _read_tables(backend: str, msi: Path) -> tuple[list[list[str]], list[list[str]]]:
    if backend == "windows":
        database = _msi().OpenDatabase(str(msi), _msi().MSIDBOPEN_READONLY)
        try:
            media = _query(
                database,
                "SELECT `DiskId`, `LastSequence`, `Cabinet` FROM `Media`",
            )
            files = _query(
                database,
                "SELECT `File`, `FileSize`, `Sequence` FROM `File`",
            )
        finally:
            database.Close()
        return media, files

    msiinfo = find_msiinfo()
    media_rows = _export_table(msiinfo, msi, "Media")
    file_rows = _export_table(msiinfo, msi, "File")
    media = [
        [
            row.get("DiskId", ""),
            row.get("LastSequence", ""),
            row.get("Cabinet", ""),
        ]
        for row in media_rows
    ]
    files = [
        [row.get("File", ""), row.get("FileSize", ""), row.get("Sequence", "")]
        for row in file_rows
    ]
    return media, files


def _stream_names(backend: str, msi: Path) -> list[str]:
    if backend == "windows":
        database = _msi().OpenDatabase(str(msi), _msi().MSIDBOPEN_READONLY)
        try:
            return [row[0] for row in _query(database, "SELECT `Name` FROM `_Streams`")]
        finally:
            database.Close()

    result = subprocess.run(
        [find_msiinfo(), "streams", str(msi)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        raise PatchError(
            f"msiinfo streams failed: {(result.stderr or result.stdout).strip()}"
        )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _present_signatures(backend: str, msi: Path) -> list[str]:
    names = _stream_names(backend, msi)
    present = []
    for signature in SIGNATURE_STREAMS:
        suffix = signature.lstrip("\x05")
        if any(name == signature or name.lstrip("\x05") == suffix for name in names):
            present.append(signature)
    return present


def _msi():
    try:
        import _msi  # type: ignore[import-not-found]
    except ImportError as error:
        raise PatchError(
            "MSI patching requires Windows and the Python _msi module "
            "(Python 3.10-3.12)"
        ) from error
    return _msi


def _query(database, sql: str) -> list[list[str]]:
    view = database.OpenView(sql)
    view.Execute(None)
    rows = []
    try:
        while True:
            record = view.Fetch()
            if record is None:
                break
            rows.append(
                [
                    record.GetString(index)
                    for index in range(1, record.GetFieldCount() + 1)
                ]
            )
    finally:
        view.Close()
    return rows


def _run(command: list[str], *, cwd: Path | None = None) -> None:
    result = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stdout or "") + (result.stderr or "")
        raise PatchError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{detail.strip()}"
        )


# ---------------------------------------------------------------------------
# MSI patch pipeline
# ---------------------------------------------------------------------------


def _extract_stream(
    backend: str, seven: str, msi: Path, stream: str, destination: Path
) -> None:
    if backend == "windows":
        destination.mkdir(parents=True, exist_ok=True)
        # Force the outer MSI (Compound) handler; otherwise 7-Zip may descend into
        # a small embedded CAB instead of extracting the stream itself.
        _run([seven, "e", "-tCompound", str(msi), stream, "-o" + str(destination), "-y"])
        return

    destination.mkdir(parents=True, exist_ok=True)
    target = destination / stream
    with target.open("wb") as handle:
        result = subprocess.run(
            [find_msiinfo(), "extract", str(msi), stream],
            stdout=handle,
            stderr=subprocess.PIPE,
            check=False,
        )
    if result.returncode != 0:
        detail = (result.stderr or b"").decode("utf-8", "replace").strip()
        raise PatchError(f"msiinfo extract {stream} failed: {detail}")


def _extract_cab(seven: str, cab: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    _run([seven, "x", str(cab), "-o" + str(destination), "-y"])


def _find_jars_with_class(files_dir: Path) -> list[Path]:
    result = []
    for path in sorted(files_dir.iterdir()):
        if not path.is_file() or path.suffix.lower() != ".jar":
            continue
        try:
            with zipfile.ZipFile(path) as jar:
                if CLASS_NAME in jar.namelist():
                    result.append(path)
        except zipfile.BadZipFile:
            continue
    return result


def _build_cab(
    backend: str,
    files_dir: Path,
    output_dir: Path,
    cabinet_name: str,
    file_keys: list[str],
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    existing = {path.name for path in files_dir.iterdir() if path.is_file()}
    missing = [name for name in file_keys if name not in existing]
    if missing:
        raise PatchError(f"CAB files are missing after extraction: {missing[:10]}")

    cabinet = output_dir / cabinet_name
    if cabinet.exists():
        cabinet.unlink()

    if backend == "windows":
        makecab = find_makecab()
        ddf = output_dir / "patch.ddf"
        files_dir_windows = str(files_dir.resolve()).replace("\\", "/")
        output_dir_windows = str(output_dir.resolve()).replace("\\", "/")
        lines = [
            f".Set CabinetNameTemplate={cabinet_name}",
            f".Set DiskDirectoryTemplate={output_dir_windows}",
            f".Set SourceDir={files_dir_windows}",
            ".Set CompressionType=MSZIP",
            ".Set CompressionMemory=21",
            ".Set Cabinet=on",
            ".Set Compress=on",
            ".Set MaxDiskSize=0",
            ".Set RptFileName=NUL",
            ".Set InfFileName=NUL",
        ]
        lines.extend(file_keys)
        ddf.write_text("\n".join(lines) + "\n", encoding="ascii")
        _run([makecab, "/F", str(ddf)])
    else:
        # gcab -z emits MSZip, which Windows Installer accepts.
        _run([find_gcab(), "-c", "-z", str(cabinet), *file_keys], cwd=files_dir)

    if not cabinet.is_file():
        raise PatchError(f"cabinet builder did not create {cabinet}")
    return cabinet


def _replace_stream(database, stream: str, cab: Path) -> None:
    view = database.OpenView("SELECT `Name`, `Data` FROM `_Streams`")
    view.Execute(None)
    try:
        while True:
            record = view.Fetch()
            if record is None:
                raise PatchError(f"MSI stream not found: {stream}")
            if record.GetString(1) == stream:
                record.SetStream(2, str(cab))
                view.Modify(_msi().MSIMODIFY_REPLACE, record)
                return
    finally:
        view.Close()


def _delete_signature_streams(database) -> list[str]:
    present = [
        name
        for name in SIGNATURE_STREAMS
        if any(row[0] == name for row in _query(database, "SELECT `Name` FROM `_Streams`"))
    ]
    for name in present:
        view = database.OpenView("SELECT `Name` FROM `_Streams`")
        view.Execute(None)
        try:
            while True:
                record = view.Fetch()
                if record is None:
                    break
                if record.GetString(1) == name:
                    view.Modify(_msi().MSIMODIFY_DELETE, record)
                    break
        finally:
            view.Close()
    return present


def _update_file_size(database, file_key: str, size: int) -> None:
    view = database.OpenView("SELECT `File`, `FileSize` FROM `File`")
    view.Execute(None)
    try:
        while True:
            record = view.Fetch()
            if record is None:
                raise PatchError(f"File table row not found: {file_key}")
            if record.GetString(1) == file_key:
                record.SetInteger(2, size)
                view.Modify(_msi().MSIMODIFY_UPDATE, record)
                return
    finally:
        view.Close()


def _apply_changes(
    backend: str,
    output: Path,
    replacements: list[tuple[str, Path]],
    patched_sizes: dict[str, int],
    strip_signature: bool,
) -> list[str]:
    if backend == "windows":
        database = _msi().OpenDatabase(str(output), _msi().MSIDBOPEN_DIRECT)
        try:
            for stream, rebuilt in replacements:
                _replace_stream(database, stream, rebuilt)
            for name, size in patched_sizes.items():
                _update_file_size(database, name, size)
            removed = _delete_signature_streams(database) if strip_signature else []
            database.Commit()
            return removed
        finally:
            database.Close()

    msibuild = find_msibuild()
    for stream, rebuilt in replacements:
        _run([msibuild, str(output), "-a", stream, str(rebuilt)])
    for name, size in patched_sizes.items():
        query = (
            f"UPDATE `File` SET `FileSize`={int(size)} "
            f"WHERE `File`='{_sql_escape(name)}'"
        )
        _run([msibuild, str(output), "-q", query])

    present = _present_signatures(backend, output) if strip_signature else []
    for name in present:
        query = (
            "DELETE FROM `_Streams` "
            f"WHERE `Name`='{_sql_escape(name)}'"
        )
        _run([msibuild, str(output), "-q", query])
    return present


def _verify_changes(
    backend: str,
    output: Path,
    patched_sizes: dict[str, int],
    strip_signature: bool,
) -> None:
    if backend == "windows":
        check_db = _msi().OpenDatabase(str(output), _msi().MSIDBOPEN_READONLY)
        try:
            rows = _query(check_db, "SELECT `File`, `FileSize` FROM `File`")
            sizes = {row[0]: int(row[1]) for row in rows}
            for name, expected in patched_sizes.items():
                if sizes.get(name) != expected:
                    raise PatchError(
                        f"File table size mismatch for {name}: "
                        f"expected {expected}, got {sizes.get(name)}"
                    )
            present = {
                name
                for name in SIGNATURE_STREAMS
                if any(
                    row[0] == name
                    for row in _query(check_db, "SELECT `Name` FROM `_Streams`")
                )
            }
            if strip_signature and present:
                raise PatchError(f"signature streams were not removed: {present}")
        finally:
            check_db.Close()
        return

    rows = _export_table(find_msiinfo(), output, "File")
    sizes = {
        row.get("File", ""): int(row.get("FileSize") or 0) for row in rows
    }
    for name, expected in patched_sizes.items():
        if sizes.get(name) != expected:
            raise PatchError(
                f"File table size mismatch for {name}: "
                f"expected {expected}, got {sizes.get(name)}"
            )
    present = _present_signatures(backend, output)
    if strip_signature and present:
        raise PatchError(f"signature streams were not removed: {present}")


def patch_msi(
    msi: Path,
    output: Path,
    new_public_key: str,
    *,
    old_public_key: str | None = None,
    strip_signature: bool = True,
    keep_temp: bool = False,
    log=print,
) -> PatchResult:
    msi = Path(msi).resolve()
    output = Path(output).resolve()
    if not msi.is_file():
        raise PatchError(f"MSI not found: {msi}")
    if msi == output:
        raise PatchError("output must not overwrite the source MSI")
    if output.exists():
        raise PatchError(f"output already exists: {output}")

    backend = detect_backend()
    seven = find_7z()

    temp = Path(tempfile.mkdtemp(prefix="ct-msi-"))
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        log(f"Copying MSI to {output}")
        shutil.copy2(msi, output)

        # Read the tables and extract the cabinets from the untouched source MSI.
        # The output copy is opened for writing only after all extraction is done.
        media, files = _read_tables(backend, msi)

        if not media:
            raise PatchError("MSI has no Media table rows")
        if not any(row[2] for row in media):
            raise PatchError("MSI has no embedded cabinets")

        file_rows = sorted(files, key=lambda row: int(row[2]))
        patched_jars: list[str] = []
        patched_sizes: dict[str, int] = {}
        replacements: list[tuple[str, Path]] = []
        found_old_key = None
        found_new_key = normalize_composite(new_public_key)
        previous_last = 0

        for disk_id, last_sequence, cabinet in media:
            last_sequence = int(last_sequence)
            if not cabinet:
                previous_last = last_sequence
                continue
            if not cabinet.startswith("#"):
                raise PatchError(f"external cabinet is not supported: {cabinet}")
            stream = cabinet[1:]
            cabinet_files = [
                row[0]
                for row in file_rows
                if previous_last < int(row[2]) <= last_sequence
            ]
            previous_last = last_sequence
            if not cabinet_files:
                continue

            cabinet_dir = temp / f"disk-{disk_id}"
            _extract_stream(backend, seven, msi, stream, cabinet_dir)
            extracted = cabinet_dir / stream
            if not extracted.is_file():
                raise PatchError(f"could not extract cabinet stream {stream}")

            files_dir = cabinet_dir / "files"
            _extract_cab(seven, extracted, files_dir)

            jars = _find_jars_with_class(files_dir)
            if not jars:
                continue
            for jar in jars:
                log(f"Patching {jar.name}")
                patched = jar.with_suffix(".patched.jar")
                old_key, _ = patch_jar(jar, patched, new_public_key, old_public_key)
                found_old_key = old_key
                patched.replace(jar)
                patched_jars.append(jar.name)
                patched_sizes[jar.name] = jar.stat().st_size

            rebuilt_dir = cabinet_dir / "rebuilt"
            rebuilt = _build_cab(
                backend, files_dir, rebuilt_dir, stream, cabinet_files
            )
            replacements.append((stream, rebuilt))

        if not patched_jars:
            raise PatchError(f"{CLASS_NAME} was not found in any embedded JAR")

        log("Updating MSI streams and tables")
        removed = _apply_changes(
            backend, output, replacements, patched_sizes, strip_signature
        )
        _verify_changes(backend, output, patched_sizes, strip_signature)

        return PatchResult(
            output=output,
            old_public_key=found_old_key or "",
            new_public_key=found_new_key,
            patched_jars=patched_jars,
            removed_signatures=removed,
        )
    except Exception:
        if output.exists():
            output.unlink()
        raise
    finally:
        if keep_temp:
            log(f"Temporary directory kept: {temp}")
        else:
            shutil.rmtree(temp, ignore_errors=True)


# ---------------------------------------------------------------------------
# CLI (optional standalone use)
# ---------------------------------------------------------------------------


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Patch the License4J public key in a Cyber Triage MSI")
    parser.add_argument("--msi", required=True, help="source MSI")
    parser.add_argument("--out", required=True, help="patched MSI output")
    parser.add_argument("--public-key", required=True, help="new composite public key file")
    parser.add_argument("--old-public-key", help="optional old composite public key file")
    parser.add_argument("--keep-signature", action="store_true", help="do not remove signature streams")
    parser.add_argument("--keep-temp", action="store_true", help="keep the temporary extraction directory")
    args = parser.parse_args(argv)

    new_key = Path(args.public_key).read_text(encoding="ascii")
    old_key = Path(args.old_public_key).read_text(encoding="ascii") if args.old_public_key else None
    try:
        result = patch_msi(
            Path(args.msi),
            Path(args.out),
            new_key,
            old_public_key=old_key,
            strip_signature=not args.keep_signature,
            keep_temp=args.keep_temp,
        )
    except PatchError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print(f"Patched: {result.output}")
    print(f"JARs: {', '.join(result.patched_jars)}")
    print(f"Removed signature streams: {result.removed_signatures}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
