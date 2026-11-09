"""disk_reader: identify what is on a physical disk Windows can't mount.

Strictly read-only. The disk handle is opened with GENERIC_READ and the only
disk I/O calls in this file are ReadFile and two query ioctls, so nothing here
can modify the disk. Needs an Administrator process to open the raw device.

Usage (elevated):  python disk_reader.py scan --disk 2 --out report.json
"""
import argparse
import collections
import csv
import ctypes
import json
import math
import os
import struct
import sys
import uuid
from ctypes import wintypes
from datetime import datetime

from ntfs_reader import Ntfs, best_name, full_path

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
OPEN_EXISTING = 3
IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x00070000
ALIGN = 4096  # a multiple of both 512 and 4K native sector sizes
INVALID_HANDLE = wintypes.HANDLE(-1).value

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = wintypes.HANDLE
k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
k32.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                         ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
k32.SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong,
                                 ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD]
k32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                wintypes.LPVOID, wintypes.DWORD,
                                ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
k32.CloseHandle.argtypes = [wintypes.HANDLE]


class RawDisk:
    """Read-only view of a physical drive with unaligned read support."""

    def __init__(self, number):
        self.path = "\\\\.\\PhysicalDrive%d" % number
        self.h = k32.CreateFileW(self.path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 None, OPEN_EXISTING, 0, None)
        if self.h == INVALID_HANDLE:
            raise ctypes.WinError(ctypes.get_last_error())
        out = self._ioctl(IOCTL_DISK_GET_LENGTH_INFO, 8)
        self.size = struct.unpack("<q", out)[0]
        geo = self._ioctl(IOCTL_DISK_GET_DRIVE_GEOMETRY, 24)
        self.sector_size = struct.unpack("<qIIII", geo)[4]

    def _ioctl(self, code, size):
        buf = ctypes.create_string_buffer(size)
        ret = wintypes.DWORD()
        if not k32.DeviceIoControl(self.h, code, None, 0, buf, size, ctypes.byref(ret), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return buf.raw[:ret.value]

    def read(self, offset, length):
        """Read any byte range. Raw devices need aligned I/O, so widen and trim."""
        start = offset - offset % ALIGN
        end = min(self.size, math.ceil((offset + length) / ALIGN) * ALIGN)
        if end <= start:
            return b""
        want = end - start
        if not k32.SetFilePointerEx(self.h, start, None, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        buf = ctypes.create_string_buffer(want)
        got = wintypes.DWORD()
        if not k32.ReadFile(self.h, buf, want, ctypes.byref(got), None):
            raise ctypes.WinError(ctypes.get_last_error())
        skip = offset - start
        return buf.raw[skip:got.value][:length]

    def close(self):
        k32.CloseHandle(self.h)


GPT_TYPES = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft Reserved",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Microsoft Basic Data",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows Recovery",
    "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3": "Windows LDM metadata",
    "af9b60a0-1431-4f62-bc68-3311714a69ad": "Windows LDM data",
    "e75caf8f-f680-4cee-afa3-b001e56efc2d": "Windows Storage Spaces",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux swap",
    "e6d6d379-f507-44c2-a23c-238f2a3df928": "Linux LVM",
    "a19d880f-05fc-4d3b-a006-743f0f84911e": "Linux RAID",
    "ca7d7ccb-63ed-4c53-861c-1742536059cc": "Linux LUKS",
    "4f68bce3-e8cd-4db1-96e7-fbcaf984b709": "Linux root (x86-64)",
    "b921b045-1df0-41c3-af44-4c6f280d3fae": "Linux root (ARM64)",
    "933ac7e1-2eb4-4f13-b844-0e14e2aef915": "Linux /home",
    "48465300-0000-11aa-aa11-00306543ecac": "macOS HFS+",
    "7c3457ef-0000-11aa-aa11-00306543ecac": "macOS APFS",
    "6a898cc3-1dd2-11b2-99a6-080020736631": "ZFS",
}
MBR_TYPES = {0x07: "NTFS/exFAT", 0x0B: "FAT32", 0x0C: "FAT32 (LBA)", 0x0E: "FAT16 (LBA)",
             0x0F: "Extended", 0x27: "Windows Recovery", 0x42: "Windows LDM", 0x82: "Linux swap",
             0x83: "Linux", 0x8E: "Linux LVM", 0xA5: "FreeBSD", 0xAF: "macOS HFS+",
             0xEE: "GPT protective", 0xEF: "EFI", 0xFD: "Linux RAID"}


def sniff(b):
    """Filesystem and container signatures in a buffer that starts at a candidate offset."""
    hits = []

    def at(off, sig):
        return b[off:off + len(sig)] == sig

    if at(3, b"NTFS    "):
        hits.append("NTFS")
    if at(3, b"-FVE-FS-"):
        hits.append("BitLocker")
    if at(3, b"EXFAT   "):
        hits.append("exFAT")
    if at(3, b"ReFS"):
        hits.append("ReFS")
    if at(510, b"\x55\xaa") and at(82, b"FAT32   "):
        hits.append("FAT32")
    if at(510, b"\x55\xaa") and (at(54, b"FAT12   ") or at(54, b"FAT16   ")):
        hits.append("FAT12/16")
    if at(0, b"XFSB"):
        hits.append("XFS")
    if at(0, b"LUKS\xba\xbe"):
        hits.append("LUKS")
    if at(0, b"hsqs"):
        hits.append("SquashFS")
    if at(32, b"NXSB"):
        hits.append("APFS")
    if at(512, b"LABELONE"):
        hits.append("LVM2 PV")
    if at(4096, b"\xfc\x4e\x2b\xa9"):
        hits.append("Linux md RAID (v1.2)")
    if at(4086, b"SWAPSPACE2"):
        hits.append("Linux swap")
    if at(1024, b"\x10\x20\xf5\xf2"):
        hits.append("F2FS")
    if at(65600, b"_BHRfS_M"):
        hits.append("Btrfs")
    if at(32769, b"CD001"):
        hits.append("ISO9660")
    if (at(1024, b"H+\x00\x04") or at(1024, b"HX\x00\x05")):
        hits.append("HFS+")
    if at(1080, b"\x53\xef") and len(b) >= 1124:
        log_block = struct.unpack("<I", b[1048:1052])[0]
        state = struct.unpack("<H", b[1082:1084])[0]
        if log_block <= 6 and state <= 7:
            label = b[1144:1160].split(b"\0")[0].decode("latin-1", "replace")
            hits.append("ext2/3/4" + (" label=%r" % label if label else ""))
    return hits


def parse_mbr(b):
    if b[510:512] != b"\x55\xaa":
        return None
    parts = []
    for i in range(4):
        e = b[446 + i * 16:462 + i * 16]
        ptype = e[4]
        if ptype:
            lba, count = struct.unpack("<II", e[8:16])
            parts.append({"type": "0x%02X" % ptype, "name": MBR_TYPES.get(ptype, "unknown"),
                          "start_lba": lba, "sectors": count})
    return parts


def parse_gpt(disk, sector, header_off):
    h = disk.read(header_off, 92)
    if h[:8] != b"EFI PART":
        return None
    entries_lba, count, esize = struct.unpack("<QII", h[72:88])
    out = {"sector_size": sector, "header_offset": header_off, "entries_lba": entries_lba,
           "disk_guid": str(uuid.UUID(bytes_le=h[56:72])), "partitions": []}
    if not (128 <= esize <= 4096 and count <= 4096):
        out["error"] = "implausible entry table (count=%d size=%d)" % (count, esize)
        return out
    table = disk.read(entries_lba * sector, count * esize)
    for i in range(len(table) // esize):
        e = table[i * esize:(i + 1) * esize]
        if e[:16] == b"\0" * 16:
            continue
        tid = str(uuid.UUID(bytes_le=e[:16]))
        first, last = struct.unpack("<QQ", e[32:48])
        if last < first or (last + 1) * sector > disk.size:
            out["implausible_entries"] = out.get("implausible_entries", 0) + 1
            out["implausible_entry_hex"] = e[:64].hex(" ")
            continue
        out["partitions"].append({
            "index": i + 1, "type_guid": tid, "type": GPT_TYPES.get(tid, "unknown"),
            "name": e[56:128].decode("utf-16-le", "replace").split("\0")[0],
            "offset": first * sector, "size": (last - first + 1) * sector})
    return out


def entropy(b):
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def sample_disk(disk, points=256, size=65536):
    """Evenly spaced samples: tells blank apart from encrypted apart from ordinary data."""
    tally = {"zero": 0, "uniform": 0, "high_entropy": 0, "structured": 0, "read_error": 0}
    span = max(disk.size - size, 1)
    for i in range(points):
        off = span * i // points
        off -= off % ALIGN
        try:
            b = disk.read(off, size)
        except OSError:
            tally["read_error"] += 1
            continue
        if not any(b):
            tally["zero"] += 1
        elif len(set(b)) == 1:
            tally["uniform"] += 1
        elif entropy(b) > 7.9:
            tally["high_entropy"] += 1
        else:
            tally["structured"] += 1
    return tally


def verdict(r):
    s, n = r["samples"], sum(r["samples"].values()) or 1
    if r["samples"]["read_error"] == n:
        return "Every sample failed to read: likely an enclosure, cable or drive fault."
    if r["partition_tables"] or r["signatures"]:
        return "Recognisable layout found; see partition tables and signatures."
    if s["zero"] + s["uniform"] == n:
        return "No layout and every sample is blank: the drive appears empty or wiped."
    if s["high_entropy"] / n > 0.9:
        return "No layout and nearly all samples look random: likely encrypted, or the enclosure is hiding the real layout."
    return "No layout found at scanned offsets, but the disk holds data: damaged or wiped table, or an unusual format."


def scan(number, sweep_gib=4):
    disk = RawDisk(number)
    try:
        r = {"disk": number, "scanned_at": datetime.now().isoformat(timespec="seconds"),
             "size_bytes": disk.size, "size_gib": round(disk.size / 2**30, 2),
             "reported_sector_size": disk.sector_size, "partition_tables": {}, "signatures": []}
        head = disk.read(0, 68 * 1024)
        r["first_64_hex"] = head[:64].hex(" ")
        r["nonzero_in_first_1mib"] = sum(1 for x in disk.read(0, 2**20) if x)

        mbr = parse_mbr(head)
        if mbr is not None:
            r["partition_tables"]["mbr"] = mbr
        for sector in (512, 4096):
            gpt = parse_gpt(disk, sector, sector)
            if gpt:
                r["partition_tables"]["gpt"] = gpt
                break
        for sector in (512, 4096):
            backup_off = disk.size - sector
            gpt = parse_gpt(disk, sector, backup_off)
            if gpt:
                r["partition_tables"]["gpt_backup"] = gpt
                break

        r["protective_mbr_missing"] = mbr is None and "gpt" in r["partition_tables"]
        declared = [p["offset"] for t in ("gpt", "gpt_backup")
                    for p in r["partition_tables"].get(t, {}).get("partitions", [])]
        offsets = sorted({0, 32256, *declared, *range(2**20, sweep_gib * 2**30, 2**20)})
        for off in offsets:
            b = disk.read(off, 68 * 1024)
            for hit in sniff(b):
                r["signatures"].append({"offset": off, "signature": hit})
        r["sweep_gib"] = sweep_gib
        r["samples"] = sample_disk(disk)
        r["verdict"] = verdict(r)
        return r
    finally:
        disk.close()


def largest_partition(disk):
    """Offset of the biggest partition in the primary GPT."""
    for sector in (disk.sector_size, 512, 4096):
        gpt = parse_gpt(disk, sector, sector)
        if gpt and gpt["partitions"]:
            return max(gpt["partitions"], key=lambda p: p["size"])["offset"]
    raise ValueError("no GPT partition found; pass --offset")


def listing(number, offset, out_dir):
    """Write files.csv for the whole volume and return a summary."""
    disk = RawDisk(number)
    try:
        offset = largest_partition(disk) if offset is None else offset
        head = disk.read(offset, 96).hex(" ")
        try:
            vol = Ntfs(disk, offset)
        except (ValueError, struct.error) as e:
            return {"disk": number, "offset": offset, "error": str(e), "partition_head_hex": head}
        files, stats = vol.index()
        cache, rows = {}, []
        for num, rec in files.items():
            if best_name(rec["names"]) is None:
                continue
            size = rec["data"]["size"] if rec["data"] else 0
            flags = rec["data"]["flags"] if rec["data"] else 0
            rows.append({"path": full_path(num, files, cache), "is_dir": rec["is_dir"], "size": size,
                         "created": rec["created"], "modified": rec["modified"],
                         "data_flags": "0x%04x" % flags, "extra_streams": rec["streams"],
                         "record": num})
        rows.sort(key=lambda r: r["path"].lower())
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "files.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ["path"])
            w.writeheader()
            w.writerows(rows)
        plain = [r for r in rows if not r["is_dir"]]
        by_ext = collections.Counter()
        for r in plain:
            by_ext[os.path.splitext(r["path"])[1].lower() or "(none)"] += r["size"]
        return {"disk": number, "volume": vol.info(), "stats": stats,
                "file_count": len(plain), "dir_count": len(rows) - len(plain),
                "total_file_bytes": sum(r["size"] for r in plain),
                "top_level": [{"path": r["path"], "is_dir": r["is_dir"], "size": r["size"],
                               "modified": r["modified"]}
                              for r in rows if r["path"].count("/") == 1],
                "largest_files": sorted(plain, key=lambda r: -r["size"])[:25],
                "bytes_by_extension": dict(by_ext.most_common(20))}
    finally:
        disk.close()


def extract(number, offset, path, dest):
    """Copy one file off the volume. Never overwrites an existing destination."""
    disk = RawDisk(number)
    try:
        offset = largest_partition(disk) if offset is None else offset
        vol = Ntfs(disk, offset)
        files, _ = vol.index(keep_data=True)
        cache = {}
        want = path.replace("\\", "/").lower()
        for num, rec in files.items():
            if best_name(rec["names"]) and full_path(num, files, cache).lower() == want:
                with open(dest, "xb") as f:
                    return {"path": path, "dest": dest, "bytes": vol.read_file(rec, f)}
        return {"path": path, "error": "not found"}
    finally:
        disk.close()


def dump_metadata(number, offset, dest_dir, max_bytes=2**20):
    """Copy small non-container files in one pass. Skips NTFS metafiles and key-like sidecars."""
    disk = RawDisk(number)
    try:
        offset = largest_partition(disk) if offset is None else offset
        vol = Ntfs(disk, offset)
        files, _ = vol.index(keep_data=True)
        os.makedirs(dest_dir, exist_ok=True)
        cache, copied, failed = {}, [], []
        for num, rec in files.items():
            if rec["is_dir"] or not rec["data"] or not best_name(rec["names"]):
                continue
            path = full_path(num, files, cache)
            name = path.rsplit("/", 1)[-1]
            ext = os.path.splitext(name)[1].lower()
            if name.startswith("$") or path.startswith("/$") or rec["data"]["size"] > max_bytes:
                continue
            if ext in (".xct", ".xvi"):
                continue
            try:
                with open(os.path.join(dest_dir, path.strip("/").replace("/", "__")), "xb") as f:
                    copied.append({"path": path, "bytes": vol.read_file(rec, f)})
            except (OSError, ValueError) as e:
                failed.append({"path": path, "error": str(e)})
        return {"dest": dest_dir, "copied": len(copied), "failed": failed}
    finally:
        disk.close()


def main():
    ap = argparse.ArgumentParser(description="Read-only physical disk inspector")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="identify partition tables, filesystems and data pattern")
    s.add_argument("--sweep-gib", type=int, default=4, help="GiB to sweep at 1 MiB steps")
    l = sub.add_parser("ls", help="list every file on an NTFS volume to files.csv")
    l.add_argument("--out-dir", required=True)
    x = sub.add_parser("extract", help="copy one file off an NTFS volume")
    x.add_argument("--path", required=True, help="path on the volume, e.g. /folder/file.bin")
    x.add_argument("--dest", required=True, help="destination file; must not already exist")
    m = sub.add_parser("metadata", help="copy small metadata files off an NTFS volume")
    m.add_argument("--dest-dir", required=True)
    for p in (s, l, x, m):
        p.add_argument("--disk", type=int, required=True, help="Windows disk number (see Get-Disk)")
        p.add_argument("--out", help="also write the JSON report to this path")
    for p in (l, x, m):
        p.add_argument("--offset", type=int, help="partition byte offset (default: largest in GPT)")
    a = ap.parse_args()
    try:
        if a.cmd == "scan":
            report = scan(a.disk, a.sweep_gib)
        elif a.cmd == "ls":
            report = listing(a.disk, a.offset, a.out_dir)
        elif a.cmd == "metadata":
            report = dump_metadata(a.disk, a.offset, a.dest_dir)
        else:
            report = extract(a.disk, a.offset, a.path, a.dest)
    except Exception as e:  # a report is the only output an elevated window leaves behind
        report = {"disk": a.disk, "error": "%s: %s" % (type(e).__name__, e)}
    text = json.dumps(report, indent=2)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
    print(text)
    return 1 if "error" in report else 0


if __name__ == "__main__":
    sys.exit(main())
