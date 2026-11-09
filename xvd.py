"""Inspect XVD/XVC headers.

The header parser reads plaintext fields and locates where cleartext ends and the
protected body begins. It decodes nothing encrypted. Field offsets for the confirmed
set are checked against a real card. Positions marked tentative, and the XvcInfo
layout used to locate key IDs, follow emoose/xvdtool (GPL-2.0):
https://github.com/emoose/xvdtool
"""
import math
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import uuid
from datetime import datetime, timedelta

HEADER_BASE = 0x200  # bytes 0x000-0x200 are the signature block; the header magic sits at 0x200
ENC_DISABLED_FLAG = 0x2
READ_ONLY_FLAG = 0x1


def _filetime(v):
    if not v or v > 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return (datetime(1601, 1, 1) + timedelta(microseconds=v // 10)).isoformat(timespec="seconds")
    except OverflowError:
        return None


def _entropy(b):
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    return -sum(c / len(b) * math.log2(c / len(b)) for c in counts if c)


def cleartext_end(data, block=4096, threshold=7.5, limit=0x20000):
    """First offset whose block looks random, i.e. where the protected body starts."""
    end = min(len(data), limit)
    for off in range(0, end - block + 1, block):
        if _entropy(data[off:off + block]) > threshold:
            return off
    return None


def parse_header(data, file_size):
    """Decode a container's header. `data` is the first bytes of the file (>= ~0x20000 ideal)."""
    if len(data) < HEADER_BASE + 0x40 or data[HEADER_BASE:HEADER_BASE + 8] != b"msft-xvd":
        return {"is_xvd": False}
    h = HEADER_BASE

    def u32(o):
        return struct.unpack("<I", data[h + o:h + o + 4])[0]

    def u64(o):
        return struct.unpack("<Q", data[h + o:h + o + 8])[0]

    def guid(o):
        return str(uuid.UUID(bytes_le=data[h + o:h + o + 16])).upper()

    flags = u32(0x08)
    payload = u64(0x18)
    return {
        "is_xvd": True,
        "flags": "0x%08X" % flags,
        "read_only": bool(flags & READ_ONLY_FLAG),
        "encrypted": not bool(flags & ENC_DISABLED_FLAG),
        "format_version": u32(0x0C),
        "created": _filetime(u64(0x10)),
        "payload_bytes": payload,
        "overhead_bytes": max(file_size - payload, 0),
        "content_id": guid(0x20),   # VDUID, matches the filename on this card
        "user_id": guid(0x30),      # UDUID
        "content_type": u32(0x84),         # tentative: validate against xvdtool XvdHeader
        "embedded_xvd_bytes": u32(0x88),   # tentative
        "cleartext_end": cleartext_end(data),
    }


def cik_files(folder):
    """Return the 48-byte CIK files exported by CikExtractor."""
    folder = Path(folder)
    if (folder / "Cik").is_dir():
        folder /= "Cik"
    files = [p for p in folder.glob("*.cik") if p.is_file() and p.stat().st_size == 48]
    if not files:
        raise RuntimeError("Choose a CikExtractor output folder containing .cik files.")
    return files


def cik_ids(folder):
    ids = set()
    for path in cik_files(folder):
        with path.open("rb") as stream:
            ids.add(stream.read(16))
    return ids


def required_cik_ids(read, size):
    """Read XVC key IDs using the header and XvcInfo layouts from xvdtool."""
    header = read(HEADER_BASE, 0x271)
    if len(header) < 0x271 or header[:8] != b"msft-xvd":
        return set()
    flags, = struct.unpack_from("<I", header, 8)
    embedded, user, info, dynamic = struct.unpack_from("<4I", header, 0x88)
    if flags & ENC_DISABLED_FLAG or info < 0xD20:
        return set()

    page = 0x1000
    def pages(length):
        return (length + page - 1) // page

    drive_size, = struct.unpack_from("<Q", header, 0x18)
    hash_pages = 0
    if not flags & 4:  # DataIntegrityDisabled
        level = pages(drive_size) + pages(user) + pages(info) + pages(dynamic)
        for _ in range(4):
            level = (level + 169) // 170
            hash_pages += level
            if level <= 1:
                break
        if flags & 0x10:  # ResiliencyEnabled duplicates each hash page
            hash_pages *= 2

    offset = page * (3 + pages(embedded) + header[0x270] + hash_pages + pages(user))
    if offset + info > size:
        raise ValueError("XVC metadata extends past the container")
    metadata = read(offset, 0xD20)
    if len(metadata) != 0xD20:
        raise ValueError("incomplete XVC metadata")
    count, = struct.unpack_from("<H", metadata, 0xD1E)
    if count > 0xC0:
        raise ValueError("invalid XVC key count")
    return {metadata[i:i + 16] for i in range(0x10, 0x10 + count * 16, 16)} - {bytes(16)}


def extract_game(exe, source, keys, dest):
    """Extract a local game container via the standalone Windows x64 xvdtool."""
    source = Path(source).resolve(strict=True)
    with source.open("rb") as stream:
        stream.seek(HEADER_BASE)
        if stream.read(8) != b"msft-xvd":
            raise RuntimeError("Select a copied XVD, XVC or MSIXVC game container.")

    key_files = cik_files(keys)

    dest = Path(dest).resolve(strict=True)
    folder = Path(tempfile.mkdtemp(prefix="Extracted-", dir=dest))
    try:
        with tempfile.TemporaryDirectory(prefix="CardViewer-xvdtool-") as tool_dir, \
                tempfile.TemporaryDirectory(prefix="CardViewer-game-", dir=dest) as game_dir:
            tool = Path(tool_dir) / "XVDTool.exe"
            shutil.copyfile(exe, tool)

            # v0.53 targets .NET Core 3.1 and finds keys beside its managed assembly.
            # Under newer .NET that assembly is unpacked from the exe on first launch.
            bundle = Path(tool_dir) / "bundle"
            env = {**os.environ, "DOTNET_ROLL_FORWARD": "LatestMajor",
                   "DOTNET_BUNDLE_EXTRACT_BASE_DIR": str(bundle)}
            probe = subprocess.run(
                [str(tool), "--help"], cwd=tool_dir, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if probe.returncode:
                raise RuntimeError("Could not start xvdtool. Check the Windows x64 release and .NET runtime.")
            assembly = next(bundle.rglob("XVDTool.dll"), tool)
            tool_keys = assembly.parent / "Cik"
            tool_keys.mkdir()
            for key in key_files:
                shutil.copyfile(key, tool_keys / key.name)

            args = [str(tool), "-nd", "-ne", "-eu", "-o", str(Path(game_dir) / "game.xvd"),
                    "-xf", str(folder), str(source)]
            with subprocess.Popen(
                args, cwd=tool_dir, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW,
            ) as process:
                extracted = missing_key = short_read = False
                for line in process.stdout:
                    extracted |= line.strip() == b"Extracted files successfully."
                    missing_key |= b"Did not find CIK " in line
                    short_read |= b"inputCount ('0')" in line or b"EndOfStreamException" in line
                if short_read:
                    raise RuntimeError("xvdtool reached missing data. Select the complete downloaded package.")
                if missing_key and not extracted:
                    raise RuntimeError("xvdtool could not find a required CIK. Check the selected Cik folder.")
                if process.wait() or not extracted or not any(path.is_file() for path in folder.rglob("*")):
                    raise RuntimeError(
                        "xvdtool could not extract this container. Check that the Cik folder contains "
                        "the keys for this game and that the destination has enough free space.")
    except BaseException:
        shutil.rmtree(folder, ignore_errors=True)
        raise
    return str(folder)
