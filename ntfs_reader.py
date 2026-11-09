"""Read-only NTFS parser that works from raw disk reads, without mounting.

Walks the Master File Table directly, so it works on volumes Windows refuses to
mount. Tolerates a boot sector whose jump bytes were blanked.

The on-disk layout (boot sector, FILE records, update-sequence fixups, runlists,
and the $STANDARD_INFORMATION, $FILE_NAME, and $DATA attributes) follows
Microsoft's NTFS format. This file is not a port of another parser.
"""
import struct
from datetime import datetime, timedelta, timezone

ROOT_RECORD = 5
ATTR_STD_INFO, ATTR_ATTR_LIST, ATTR_FILE_NAME, ATTR_DATA = 0x10, 0x20, 0x30, 0x80
FLAG_COMPRESSED, FLAG_ENCRYPTED, FLAG_SPARSE = 0x0001, 0x4000, 0x8000
REF_MASK = (1 << 48) - 1


def filetime(v):
    if not v or v > 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        t = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=v // 10)
        return t.isoformat(timespec="seconds")
    except OverflowError:
        return None


def decode_runs(b):
    """NTFS runlist to [(cluster_count, lcn or None when sparse)]."""
    runs, i, lcn = [], 0, 0
    while i < len(b) and b[i]:
        header = b[i]
        nlen, noff = header & 0xF, header >> 4
        i += 1
        if i + nlen + noff > len(b):
            raise ValueError("truncated runlist")
        count = int.from_bytes(b[i:i + nlen], "little")
        i += nlen
        if noff:
            lcn += int.from_bytes(b[i:i + noff], "little", signed=True)
            runs.append((count, lcn))
        else:
            runs.append((count, None))
        i += noff
    return runs


def apply_fixups(rec):
    """Restore the bytes NTFS swaps for torn-write detection. None when torn."""
    usa_off, usa_cnt = struct.unpack("<HH", rec[4:8])
    if usa_cnt < 2:
        return rec
    stride = len(rec) // (usa_cnt - 1)
    if usa_off + usa_cnt * 2 > len(rec) or stride < 512:
        return None
    out = bytearray(rec)
    check = rec[usa_off:usa_off + 2]
    for i in range(1, usa_cnt):
        end = i * stride
        if out[end - 2:end] != check:
            return None
        out[end - 2:end] = rec[usa_off + i * 2:usa_off + i * 2 + 2]
    return bytes(out)


def parse_record(raw, keep_data=False):
    """Parse one MFT record. Returns None for anything that isn't a valid FILE record."""
    if raw[:4] != b"FILE":
        return None
    rec = apply_fixups(raw)
    if rec is None:
        return None
    flags = struct.unpack("<H", rec[22:24])[0]
    base = struct.unpack("<Q", rec[32:40])[0] & REF_MASK
    out = {"in_use": bool(flags & 1), "is_dir": bool(flags & 2), "base": base,
           "names": [], "data": None, "modified": None, "created": None,
           "has_attr_list": False, "streams": 0, "named": {}, "security_id": None}
    pos = struct.unpack("<H", rec[20:22])[0]
    while pos + 16 <= len(rec):
        atype, alen = struct.unpack("<II", rec[pos:pos + 8])
        if atype == 0xFFFFFFFF or alen < 16 or pos + alen > len(rec):
            break
        a = rec[pos:pos + alen]
        nonres, name_len = a[8], a[9]
        aflags = struct.unpack("<H", a[12:14])[0]
        stream = ""
        if atype == ATTR_DATA and name_len:
            name_off = struct.unpack("<H", a[10:12])[0]
            stream = a[name_off:name_off + name_len * 2].decode("utf-16-le", "replace")
        if atype == ATTR_ATTR_LIST:
            out["has_attr_list"] = True
        elif not nonres:
            clen, coff = struct.unpack("<IH", a[16:22])
            content = a[coff:coff + clen]
            if atype == ATTR_STD_INFO and len(content) >= 16:
                created, modified = struct.unpack("<QQ", content[:16])
                out["created"], out["modified"] = filetime(created), filetime(modified)
                if len(content) >= 56:  # NTFS 3.x stores the permission rule's ID here
                    out["security_id"] = struct.unpack("<I", content[52:56])[0]
            elif atype == ATTR_FILE_NAME and len(content) >= 66:
                n = content[64]
                out["names"].append({
                    "parent": struct.unpack("<Q", content[:8])[0] & REF_MASK,
                    "namespace": content[65],
                    "name": content[66:66 + n * 2].decode("utf-16-le", "replace")})
            elif atype == ATTR_DATA:
                if name_len:
                    out["streams"] += 1
                    if keep_data:
                        out["named"][stream] = {"size": clen, "init": clen, "flags": aflags, "resident": True,
                                                "content": content, "runs": []}
                elif out["data"] is None:
                    out["data"] = {"size": clen, "init": clen, "flags": aflags, "resident": True,
                                   "content": content if keep_data else None, "runs": []}
        elif atype == ATTR_DATA:
            if name_len:
                start_vcn = struct.unpack("<Q", a[16:24])[0]
                if start_vcn == 0:
                    out["streams"] += 1
                if keep_data:
                    run_off = struct.unpack("<H", a[32:34])[0]
                    runs = decode_runs(a[run_off:])
                    if start_vcn == 0:
                        real, init = struct.unpack("<QQ", a[48:64])
                        out["named"][stream] = {"size": real, "init": init, "flags": aflags, "resident": False,
                                                "content": None, "runs": runs}
                    elif stream in out["named"]:
                        out["named"][stream]["runs"].extend(runs)
            else:
                start_vcn = struct.unpack("<Q", a[16:24])[0]
                run_off = struct.unpack("<H", a[32:34])[0]
                runs = decode_runs(a[run_off:]) if keep_data or start_vcn == 0 else []
                if start_vcn == 0 and out["data"] is None:
                    real, init = struct.unpack("<QQ", a[48:64])
                    out["data"] = {"size": real, "init": init, "flags": aflags, "resident": False,
                                   "content": None, "runs": runs}
                elif out["data"] is not None and keep_data:
                    out["data"]["runs"].extend(runs)
                elif keep_data:
                    out["data_tail"] = out.get("data_tail", []) + runs
        pos += alen
    return out


class Ntfs:
    def __init__(self, disk, offset):
        self.disk, self.offset = disk, offset
        boot = disk.read(offset, 512)
        self.boot = boot
        self.boot_hex = boot[:96].hex(" ")
        if boot[3:11] != b"NTFS    ":
            raise ValueError("no NTFS signature at offset %d (got %r)" % (offset, boot[3:11]))
        self.bps = struct.unpack("<H", boot[11:13])[0]
        spc = boot[13]
        self.spc = spc if spc <= 128 else 1 << (256 - spc)
        self.cluster = self.bps * self.spc
        self.total_sectors = struct.unpack("<Q", boot[40:48])[0]
        self.mft_lcn = struct.unpack("<Q", boot[48:56])[0]
        crec = struct.unpack("<b", boot[64:65])[0]
        self.rec_size = crec * self.cluster if crec > 0 else 1 << -crec
        self.volume_serial = boot[72:80][::-1].hex()
        first = disk.read(self._lcn(self.mft_lcn), self.rec_size)
        mft = parse_record(first, keep_data=True)
        if not mft or not mft["data"]:
            raise ValueError("$MFT record unreadable at LCN %d (starts %s)"
                             % (self.mft_lcn, first[:16].hex(" ")))
        self.mft_size = mft["data"]["size"]
        self.mft_runs = mft["data"]["runs"]
        self.mft_fragmented = mft["has_attr_list"]

    def _lcn(self, lcn):
        return self.offset + lcn * self.cluster

    def info(self):
        return {"offset": self.offset, "bytes_per_sector": self.bps, "cluster_size": self.cluster,
                "volume_size_bytes": self.total_sectors * self.bps, "mft_lcn": self.mft_lcn,
                "mft_record_size": self.rec_size, "mft_size_bytes": self.mft_size,
                "mft_runs": len(self.mft_runs), "mft_has_attribute_list": self.mft_fragmented,
                "volume_serial": self.volume_serial, "boot_sector_hex": self.boot_hex}

    def records(self, keep_data=False):
        """Yield (record_number, parsed) for every valid record, reading the MFT in order."""
        num, remaining = 0, self.mft_size
        for count, lcn in self.mft_runs:
            run_bytes = min(count * self.cluster, remaining)
            remaining -= run_bytes
            if lcn is None:
                num += run_bytes // self.rec_size
                continue
            done = 0
            while done < run_bytes:
                want = min(16 * 2**20, run_bytes - done)
                chunk = self.disk.read(self._lcn(lcn) + done, want)
                for i in range(0, len(chunk) - self.rec_size + 1, self.rec_size):
                    try:
                        parsed = parse_record(chunk[i:i + self.rec_size], keep_data)
                    except (ValueError, struct.error):
                        parsed = None
                    if parsed:
                        yield num, parsed
                    num += 1
                done += want

    def index(self, keep_data=False):
        """All in-use files keyed by record, with extension records folded into their base."""
        files, stats, extensions = {}, {"valid_records": 0, "deleted_records": 0}, []
        for num, r in self.records(keep_data):
            stats["valid_records"] += 1
            if not r["in_use"]:
                stats["deleted_records"] += 1
            elif r["base"]:
                extensions.append(r)
            else:
                files[num] = r
        for ext in extensions:
            base = files.get(ext["base"])
            if not base:
                continue
            base["names"].extend(ext["names"])
            if base["data"] is None and ext["data"]:
                base["data"] = ext["data"]
            elif base["data"] and keep_data:
                base["data"]["runs"].extend(ext.get("data_tail", []))
        return files, stats

    def read_file(self, record, sink):
        """Stream a file's unnamed data to sink. Refuses formats it can't decode faithfully."""
        d = record["data"]
        if d is None:
            raise ValueError("no data stream")
        if d["flags"] & (FLAG_COMPRESSED | FLAG_ENCRYPTED):
            raise ValueError("file is NTFS-compressed or EFS-encrypted (flags 0x%04x)" % d["flags"])
        if d["resident"]:
            sink.write(d["content"])
            return d["size"]
        written = 0
        for count, lcn in d["runs"]:
            run_bytes = count * self.cluster
            done = 0
            while done < run_bytes and written < d["size"]:
                want = min(16 * 2**20, run_bytes - done, d["size"] - written)
                if lcn is not None and written < d["init"]:
                    want = min(want, d["init"] - written)  # never read past valid data
                if lcn is None or written >= d["init"]:
                    sink.write(b"\0" * want)
                else:
                    sink.write(self.disk.read(self._lcn(lcn) + done, want))
                done += want
                written += want
        if written != d["size"]:
            raise ValueError("runlist covered %d of %d bytes" % (written, d["size"]))
        return written

    def read_prefix(self, record, length):
        """Read just the first `length` bytes of a file's data."""
        return self.read_range(record, 0, length)

    def read_range(self, record, offset, length):
        """Read a range of the unnamed data stream without reading earlier runs."""
        d = record["data"]
        if d is None:
            return b""
        end = min(offset + length, d["size"])
        if d["resident"]:
            return (d["content"] or b"")[offset:end]
        out = bytearray()
        start = 0
        for count, lcn in d["runs"]:
            run_end = start + count * self.cluster
            first, last = max(start, offset), min(run_end, end)
            if first < last:
                initialized = max(0, min(last, d["init"]) - first) if lcn is not None else 0
                if initialized:
                    data = self.disk.read(self._lcn(lcn) + first - start, initialized)
                    if len(data) != initialized:
                        raise OSError("short read in NTFS data run")
                    out.extend(data)
                out.extend(bytes(last - first - initialized))
            if run_end >= end:
                break
            start = run_end
        return bytes(out)



def best_name(names):
    """Prefer the long Win32 name over the 8.3 DOS alias."""
    ranked = sorted(names, key=lambda n: {1: 0, 3: 1, 0: 2, 2: 3}.get(n["namespace"], 4))
    return ranked[0] if ranked else None


def full_path(num, files, cache):
    """Resolve the path of a record, tolerating missing parents and loops."""
    if num in cache:
        return cache[num]
    chain, cur = [], num
    seen = set()
    while cur != ROOT_RECORD:
        if cur in cache:
            prefix = cache[cur]
            break
        rec = files.get(cur)
        name = best_name(rec["names"]) if rec else None
        if name is None or cur in seen:
            prefix = "<orphan-%d>" % cur
            break
        seen.add(cur)
        chain.append((cur, name["name"]))
        cur = name["parent"]
    else:
        prefix = ""
    for rec_num, name in reversed(chain):
        prefix = prefix + "/" + name
        cache[rec_num] = prefix
    return prefix or "/"
