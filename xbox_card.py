"""Turn a raw NTFS volume into a card model: titles, sizes and the full file list.

No GUI code lives here. Disk access is read-only, through disk_reader.RawDisk.
The optional catalog lookup sends Store IDs to Microsoft's display catalog:
https://displaycatalog.mp.microsoft.com
ConsoleAssociations and LastConsole layouts are inferred from this card, not from a published spec.
"""
import hashlib
import io
import json
import os
import re
import shutil
import struct
import tempfile
import threading
import urllib.request
import uuid
from datetime import datetime, timedelta

import ntfs_security
import xvd
from disk_reader import RawDisk, largest_partition
from ntfs_reader import Ntfs, best_name, full_path

GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
CONTAINER = re.compile(r"^/(%s|.+\.UW9)$" % GUID)
PLS_FILE = re.compile(r"^/PLS/[^/]+/(%s)-PLS$" % GUID, re.IGNORECASE)
CATALOG_URL = "https://displaycatalog.mp.microsoft.com/v7.0/products?bigIds=%s&market=US&languages=en-US"
KIND_LABELS = {"Game": "Game", "Application": "App", "Durable": "Add-on"}
UNKNOWN = "Unknown"
MANIFEST_NAME = "_copy_manifest.json"


def parse_xvs(raw):
    """Pull identity fields from an .xvs sidecar (UTF-16 JSON). Empty dict if unreadable."""
    try:
        j = json.loads(raw.decode("utf-16-le").rstrip("\x00"))
    except (UnicodeDecodeError, ValueError):
        return {}
    req, status = j.get("Request") or {}, j.get("Status") or {}
    sources = req.get("Sources") or {}
    paths = sources.get("ForegroundCrdPaths") or sources.get("BackgroundCrdPaths") or []
    current = (status.get("Source") or {}).get("Current") or {}
    return {"store": req.get("StoreId") or "",
            "package": paths[0].rsplit("/", 1)[-1] if paths else "",
            "platform": current.get("Platform") or "",
            "build": current.get("BuildId") or (j.get("Constraint") or {}).get("PackageBuildId") or ""}


def package_title(package):
    """Readable fallback title when the catalog has no answer."""
    name = package.split("_", 1)[0]
    name = re.sub(r"-GAM\d*$", "", name)
    return name.rsplit(".", 1)[-1] if name.count(".") == 1 else name


def package_version(package):
    parts = package.split("_")
    return parts[1] if len(parts) > 1 and re.fullmatch(r"[\d.]+", parts[1]) else ""


def permission_rows(model):
    """Permission rules with the files that use each, most-used first."""
    users = {}
    for f in model["files"]:
        users.setdefault(f.get("security_id"), []).append(f["path"])
    rows = [{"id": sec_id, "rule": rule, "summary": ntfs_security.summary(rule),
             "owner": ntfs_security.account_name(rule["owner"]) if rule["owner"] else "None listed",
             "files": users.get(sec_id, [])}
            for sec_id, rule in model.get("security", {}).items()]
    rows.sort(key=lambda r: (-len(r["files"]), r["id"]))
    return rows


def file_permission(model, f):
    """Plain description of a file's permission rule."""
    sec_id = f.get("security_id")
    rule = model.get("security", {}).get(sec_id)
    if rule is None:
        return "No permission rule found for this file."
    return "Rule %d\n%s" % (sec_id, ntfs_security.describe(rule))


def read_security(vol, records):
    """Decode $Secure's rules. Returns (rules, error text or None)."""
    stream = (records.get(9) or {}).get("named", {}).get("$SDS")  # record 9 is always $Secure
    if not stream:
        return {}, "This disk has no $Secure permission data."
    sink = io.BytesIO()
    try:
        vol.read_file({"data": stream}, sink)
    except (OSError, ValueError) as e:
        return {}, "Couldn't read the permission data: %s" % e
    return ntfs_security.parse_sds(sink.getvalue()), None


def build_model(files, xvs, volume_bytes=None, used_bytes=None):
    """files: dicts with path/is_dir/size/created/modified. xvs: {container name: raw bytes}."""
    pls = {}
    for f in files:
        m = PLS_FILE.match(f["path"])
        if m:
            pls[m.group(1).lower()] = f
    titles = []
    for f in files:
        m = CONTAINER.match(f["path"])
        if not m or f["is_dir"]:
            continue
        cid = m.group(1)
        info = parse_xvs(xvs[cid]) if cid in xvs else {}
        is_app = cid.endswith(".UW9")
        package = info.get("package", "") or (cid[:-4] if is_app else "")
        store = info.get("store", "")
        local = pls.pop(cid.lower(), None)
        titles.append({
            "id": cid, "store": store, "package": package,
            "title": package_title(package) if package else "Unidentified container",
            "kind": "App" if is_app else ("Game" if info else UNKNOWN),
            "size": f["size"], "pls": local["size"] if local else 0,
            "created": f["created"], "modified": f["modified"],
            "version": package_version(package), "platform": info.get("platform", ""),
            "build": info.get("build", ""), "title_source": "package" if package else "none", "xvd": None})
    for cid, f in pls.items():  # local data whose container isn't on this card
        titles.append({
            "id": cid.upper(), "store": "", "package": "", "title": "Local data with no installed title",
            "kind": UNKNOWN, "size": 0, "pls": f["size"], "created": f["created"],
            "modified": f["modified"], "version": "", "platform": "", "build": "", "title_source": "none",
            "xvd": None})
    titles.sort(key=lambda t: -(t["size"] + t["pls"]))
    return {"files": files, "titles": titles, "volume_bytes": volume_bytes, "used_bytes": used_bytes,
            "catalog": "not requested", "security": {}, "security_error": None, "card_records": {}}


def read_card(number, progress=lambda msg: None):
    """Read a physical disk into a model. Raises OSError or ValueError on failure."""
    disk = RawDisk(number)
    try:
        progress("Finding the partition")
        vol = Ntfs(disk, largest_partition(disk))
        progress("Reading the file table")
        records, _ = vol.index(keep_data=True)
        cache, files, xvs, card_records, headers = {}, [], {}, {}, {}
        progress("Reading title metadata")
        for num, rec in records.items():
            if not best_name(rec["names"]):
                continue
            path = full_path(num, records, cache)
            d = rec["data"]
            files.append({"path": path, "is_dir": rec["is_dir"], "size": d["size"] if d else 0,
                          "created": rec["created"], "modified": rec["modified"],
                          "security_id": rec["security_id"]})
            if CONTAINER.match(path) and not rec["is_dir"] and d and d["size"] > 2**20:
                try:
                    headers[path.lower().lstrip("/")] = (vol.read_prefix(rec, 0x20000), d["size"])
                except (OSError, ValueError):
                    pass
            if path.lower().lstrip("/") in CARD_FILES and d and d["size"] < 2**20:
                sink = io.BytesIO()
                try:
                    vol.read_file(rec, sink)
                    card_records[path.lower().lstrip("/")] = sink.getvalue()
                except ValueError:
                    pass
            if path.lower().endswith(".xvs") and path.count("/") == 1 and d and d["size"] < 2**20:
                sink = io.BytesIO()
                try:
                    vol.read_file(rec, sink)
                    xvs[path[1:-4]] = sink.getvalue()
                except ValueError:
                    pass
        files.sort(key=lambda f: f["path"].lower())
        used = None
        if 6 in records and records[6]["data"]:  # record 6 is always $Bitmap
            progress("Measuring used space")
            sink = io.BytesIO()
            vol.read_file(records[6], sink)
            used = int.from_bytes(sink.getvalue(), "little").bit_count() * vol.cluster
        progress("Reading permissions")
        model = build_model(files, xvs, vol.total_sectors * vol.bps, used)
        model["security"], model["security_error"] = read_security(vol, records)
        model["card_records"] = card_records
        model["boot"] = bytes(vol.boot[:512])
        for t in model["titles"]:
            hs = headers.get(t["id"].lower())
            if hs:
                t["xvd"] = xvd.parse_header(hs[0], hs[1])
        return model
    finally:
        disk.close()


class Cancelled(Exception):
    """The user stopped an extraction."""


def package_files(model, title):
    """Every file belonging to a title, as model file dicts: container, sidecars and local data."""
    by_path = {f["path"].lower(): f for f in model["files"] if not f["is_dir"]}
    cid = title["id"].lower()
    wanted = ["/" + cid + s for s in ("", ".xct", ".xvi", ".xvs")]
    if title.get("build"):
        wanted.append("/%s.pfm" % title["build"].lower())
    found = [by_path[p] for p in wanted if p in by_path]
    found += [f for p, f in by_path.items()
              if p.startswith("/pls/") and p.endswith("/%s-pls" % cid)]
    return found


def package_size(model, title):
    return sum(f["size"] for f in package_files(model, title))


CARD_FILES = {"consoleassociations": "Console link record", "lastconsole": "Last-used console record",
              "storagestate.json": "Card storage state"}
PACKAGE_LABELS = {"Game": "Game package", "Add-on": "Add-on package", "App": "App package"}
SIDECAR_LABELS = {".xvs": "Install record", ".xvi": "Package support file (.xvi)",
                  ".xct": "Package support file (.xct)", ".pfm": "Package build file (.pfm)"}


def _guid_date(guid):
    """The timestamp inside a version 1 GUID, which may not be a real creation date."""
    if guid.version != 1:
        return "none"
    try:
        return (datetime(1582, 10, 15) + timedelta(microseconds=guid.time // 10)).strftime("%Y-%m-%d")
    except OverflowError:
        return "none"


def parse_console_associations(raw):
    """Fields of ConsoleAssociations. The layout is inferred from one real card, not documented."""
    if len(raw) < 16:
        return {"error": "file is too short to decode"}
    version, _, count, offset = struct.unpack("<IIII", raw[:16])
    out = {"version": version, "count": count, "offset": offset, "first_id": None, "first_value": None}
    if count and offset + 20 <= len(raw):
        out["first_id"] = uuid.UUID(bytes_le=raw[offset:offset + 16])
        out["first_value"] = struct.unpack("<I", raw[offset + 16:offset + 20])[0]
    elif count:
        out["error"] = "the list points outside the file"
    return out


def _hex_lines(raw):
    """Hex view of the non-empty part of a record, in 16-byte rows."""
    end = max((i for i, x in enumerate(raw) if x), default=-1) + 1
    rows = ["%04x  %s" % (o, raw[o:o + 16].hex(" ")) for o in range(0, end, 16)]
    if end < len(raw):
        rows.append("(remaining %d bytes are empty)" % (len(raw) - end))
    return rows or ["(empty)"]


def _modified(model, name):
    for f in model["files"]:
        if f["path"].lower() == "/" + name:
            return (f["modified"] or "unknown")[:10]
    return "unknown"


def card_info_text(model):
    """Plain description of the card's own records, separating facts from interpretation."""
    records = model.get("card_records", {})
    if not records:
        return "This disk has no Xbox card records."
    lines = []
    raw = records.get("consoleassociations")
    last_raw = records.get("lastconsole", b"")
    last = uuid.UUID(bytes_le=last_raw) if len(last_raw) == 16 else None
    if raw is None:
        lines += ["LINKED CONSOLES", "  ConsoleAssociations isn't on this disk.", ""]
    else:
        info = parse_console_associations(raw)
        lines += ["LINKED CONSOLES (ConsoleAssociations)"]
        if "error" in info:
            lines.append("  Couldn't decode: %s" % info["error"])
        else:
            lines.append("  Consoles listed: %d" % info["count"])
            if info["first_id"]:
                lines += ["  Console ID:      %s" % str(info["first_id"]).upper(),
                          "  Date inside ID:  %s (may not be a real date)" % _guid_date(info["first_id"]),
                          "  Same as last-used console: %s" % ("yes" if last == info["first_id"] else "no")]
            if info["count"] > 1:
                lines.append("  Only the first ID is decoded, since no multi-console card has been checked.")
        lines += ["  File last updated: %s" % _modified(model, "consoleassociations"), ""]
    lines += ["LAST-USED CONSOLE (LastConsole)",
              "  Console ID:      %s" % (str(last).upper() if last else "not readable"),
              "  File last updated: %s" % _modified(model, "lastconsole"), ""]
    state = records.get("storagestate.json")
    lines.append("THIS CARD (StorageState.json)")
    if state is None:
        lines.append("  StorageState.json isn't on this disk.")
    else:
        try:
            text = state.decode("utf-16") if state[:2] in (b"\xff\xfe", b"\xfe\xff") else (
                state.decode("utf-16-le") if state[1:2] == b"\0" else state.decode("utf-8-sig"))
            doc = json.loads(text.rstrip("\x00"))
            for key, value in doc.items():
                lines.append("  %s: %s" % (key, str(value).upper() if key == "DeviceId" else value))
        except (UnicodeDecodeError, ValueError, AttributeError):
            lines.append("  Couldn't decode this file.")
    lines += ["  File last updated: %s" % _modified(model, "storagestate.json"), "",
              "WHAT'S CONFIRMED AND WHAT ISN'T",
              "  Confirmed: the IDs and dates above are exactly what these files contain.",
              "  Interpreted: Microsoft doesn't document these files. Calling these IDs \"linked\" and",
              "  \"last-used\" consoles comes from the file names and layout.",
              "  These files hold no keys, licenses or account names. Editing them isn't supported here.",
              "", "RAW BYTES"]
    for name in ("consoleassociations", "lastconsole"):
        if name in records:
            lines.append("  %s" % name)
            lines += ["    " + row for row in _hex_lines(records[name])]
    return "\n".join(lines)


def file_labels(model):
    """{path: (belongs to, what it is)} in plain words for every file in the model.

    Ownership comes from the card's own links between IDs. The .xvs record's contents are
    confirmed; .xvi, .xct and .pfm are only named by type because their format isn't documented.
    """
    labels = {}
    for t in model["titles"]:
        for f in package_files(model, t):
            path = f["path"]
            ext = os.path.splitext(path)[1].lower()
            if path.lower().startswith("/pls/"):
                what = "Local data"
            elif ext in SIDECAR_LABELS and not path.lower().endswith(".uw9"):
                what = SIDECAR_LABELS[ext]
            else:
                what = PACKAGE_LABELS.get(t["kind"], "Unidentified package")
            labels[path] = (t["title"], what)
    for f in model["files"]:
        path = f["path"]
        if path in labels:
            continue
        low = path.lower()
        if path.startswith("/$"):
            labels[path] = ("Card filesystem", "NTFS system folder" if f["is_dir"] else "NTFS system file")
        elif low.lstrip("/") in CARD_FILES:
            labels[path] = ("Xbox card", CARD_FILES[low.lstrip("/")])
        elif low == "/pls" or (low.startswith("/pls/") and f["is_dir"]):
            labels[path] = ("Xbox card", "Local data folder")
        else:
            labels[path] = ("Not linked to a title", "Folder" if f["is_dir"] else "Unrecognized file")
    return labels


def folder_name(title):
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "", title["title"]).strip().rstrip(".")
    return "%s [%s]" % (name[:80] or "package", title["id"][:8])


class _Sink:
    """File sink that hashes, reports progress and honours cancellation as data arrives."""

    def __init__(self, f, on_bytes, cancel):
        self.f, self.on_bytes, self.cancel = f, on_bytes, cancel
        self.sha = hashlib.sha256()

    def write(self, b):
        if self.cancel.is_set():
            raise Cancelled()
        self.f.write(b)
        self.sha.update(b)
        self.on_bytes(len(b))


def _hash_file(path, on_bytes, cancel):
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            if cancel.is_set():
                raise Cancelled()
            b = f.read(16 * 2**20)
            if not b:
                return sha.hexdigest()
            sha.update(b)
            on_bytes(len(b))


def _records_by_path(records):
    cache, by_path = {}, {}
    for num, rec in records.items():
        if best_name(rec["names"]) and not rec["is_dir"]:
            by_path[full_path(num, records, cache).lower()] = rec
    return by_path


def _target_path(folder, card_path):
    """Where a card file lands, refusing names that could escape the destination folder."""
    parts = card_path.strip("/").split("/")
    if any(p in ("", ".", "..") or re.search(r'[<>:"\\|?*\x00-\x1f]', p) for p in parts):
        raise ValueError("file name can't be saved safely on Windows")
    return os.path.join(folder, *parts)


def _copy_one(vol, rec, f, folder, on_bytes, cancel):
    """Copy and verify one file. A partial .part file never survives a failure."""
    target = _target_path(folder, f["path"])
    os.makedirs(os.path.dirname(target), exist_ok=True)
    part = target + ".part"
    try:
        with open(part, "xb") as out:
            sink = _Sink(out, on_bytes, cancel)
            if rec["data"] is not None:  # some system files have no main data, only an empty entry
                vol.read_file(rec, sink)
        digest = sink.sha.hexdigest()
        if _hash_file(part, on_bytes, cancel) != digest:
            raise OSError("the copy differs from what was read")
        os.rename(part, target)
    except BaseException:
        if os.path.exists(part):
            os.remove(part)
        raise
    entry = {"path": f["path"], "size": f["size"], "sha256": digest}
    if rec.get("streams"):
        entry["named_streams_not_copied"] = rec["streams"]
    return entry


def expand_selection(model, chosen):
    """Files for a selection, where a chosen folder means everything inside it."""
    paths = {}
    for c in chosen:
        if c["is_dir"]:
            prefix = c["path"].rstrip("/").lower() + "/"
            for f in model["files"]:
                if not f["is_dir"] and f["path"].lower().startswith(prefix):
                    paths[f["path"]] = f
        else:
            paths[c["path"]] = c
    return list(paths.values())


def copy_files(vol, records, files, folder, on_bytes, cancel):
    """Copy files keeping the card's layout, for bulk copies where finished work must survive.

    One bad file is recorded and skipped, and cancelling keeps what's already verified.
    The manifest says exactly what happened either way.
    """
    os.makedirs(folder)  # raises if it exists, so an earlier copy is never overwritten
    by_path = _records_by_path(records)
    copied, failed, cancelled = [], [], False
    for f in files:
        try:
            rec = by_path.get(f["path"].lower())
            if rec is None:
                raise ValueError("no longer found in the file table")
            copied.append(_copy_one(vol, rec, f, folder, on_bytes, cancel))
        except Cancelled:
            cancelled = True
            break
        except (OSError, ValueError, struct.error) as e:
            failed.append({"path": f["path"], "size": f["size"], "error": str(e)})
    result = {"folder": folder, "requested": len(files), "copied": copied, "failed": failed,
              "cancelled": cancelled, "complete": not failed and not cancelled,
              "copied_at": datetime.now().isoformat(timespec="seconds")}
    with open(os.path.join(folder, MANIFEST_NAME), "w", encoding="utf-8") as m:
        json.dump(result, m, indent=1, ensure_ascii=False)
    return result


def export_files(number, model, files, dest_root, progress, cancel):
    """Copy any files from a disk into a new dated folder. progress(done, total, label)."""
    need = sum(f["size"] for f in files)
    free = shutil.disk_usage(dest_root).free
    if need + 2**30 > free:
        raise OSError("not enough space: needs %.1f GB plus 1 GB spare, the destination has %.1f GB free"
                      % (need / 1e9, free / 1e9))
    disk = RawDisk(number)
    try:
        vol = Ntfs(disk, largest_partition(disk))
        records, _ = vol.index(keep_data=True)
        done, total = [0], need * 2  # each byte is read once and verified once

        def on_bytes(n):
            done[0] += n
            progress(done[0], total, "card files")
        folder = os.path.join(dest_root, "Card files " + datetime.now().strftime("%Y-%m-%d %H%M%S"))
        return copy_files(vol, records, files, folder, on_bytes, cancel)
    finally:
        disk.close()


def export_title(vol, records, model, title, dest_root, on_bytes, cancel):
    """Copy one title to a new folder and verify it. Only ever writes inside that new folder.

    A folder without manifest.json is incomplete. Failed or cancelled copies are removed.
    """
    folder = os.path.join(dest_root, folder_name(title))
    os.makedirs(folder)  # raises if it exists, so an earlier copy is never overwritten
    try:
        by_path = _records_by_path(records)
        entries = [_copy_one(vol, by_path[f["path"].lower()], f, folder, on_bytes, cancel)
                   for f in package_files(model, title)]
        manifest = {"title": title["title"], "store_id": title["store"], "package": title["package"],
                    "container_id": title["id"], "build": title.get("build", ""),
                    "copied_at": datetime.now().isoformat(timespec="seconds"), "files": entries}
        with open(os.path.join(folder, "manifest.json"), "w", encoding="utf-8") as m:
            json.dump(manifest, m, indent=1, ensure_ascii=False)
        return folder
    except BaseException:
        shutil.rmtree(folder, ignore_errors=True)
        raise


def export_titles(number, model, titles, dest_root, progress, cancel):
    """Copy titles from a disk. progress(done_bytes, total_bytes, label). Returns folders written."""
    need = sum(package_size(model, t) for t in titles)
    free = shutil.disk_usage(dest_root).free
    if need + 2**30 > free:
        raise OSError("not enough space: needs %.1f GB plus 1 GB spare, the destination has %.1f GB free"
                      % (need / 1e9, free / 1e9))
    disk = RawDisk(number)
    try:
        vol = Ntfs(disk, largest_partition(disk))
        records, _ = vol.index(keep_data=True)
        done, total, folders = [0], need * 2, []  # each byte is read once and verified once
        for t in titles:
            def on_bytes(n, label=t["title"]):
                done[0] += n
                progress(done[0], total, label)
            folders.append(export_title(vol, records, model, t, dest_root, on_bytes, cancel))
        return folders
    finally:
        disk.close()


def copy_smallest_cik_match(number, model, ids, dest, progress):
    """Scan installed containers and copy the smallest fully matched package."""
    disk = RawDisk(number)
    try:
        vol = Ntfs(disk, largest_partition(disk))
        records, _ = vol.index(keep_data=True)
        by_path = _records_by_path(records)
        checked = skipped = 0
        matches = []
        for title in model["titles"]:
            if not title["size"]:
                continue
            checked += 1
            path = "/" + title["id"].lower()
            rec = by_path.get(path)
            if not rec or not rec["data"] or rec["data"]["size"] != title["size"]:
                skipped += 1
                continue
            try:
                required = xvd.required_cik_ids(
                    lambda offset, length: vol.read_range(rec, offset, length), title["size"])
            except (OSError, ValueError):
                skipped += 1
                continue
            if required and required <= ids:
                matches.append(title)

        if not matches:
            return checked, skipped, 0, None
        title = min(matches, key=lambda t: (package_size(model, t), t["id"].lower()))
        # Allow for the verified package, xvdtool's temporary copy, and extracted files.
        need = package_size(model, title) + 2 * title["size"]
        if shutil.disk_usage(dest).free < need:
            raise OSError("Choose a destination with at least %.1f GB free for %s." % (need / 1e9, title["title"]))
        progress("Copying and verifying " + title["title"])
        batch = tempfile.mkdtemp(prefix="CIK-match-", dir=dest)
        try:
            folder = export_title(vol, records, model, title, batch, lambda n: None, threading.Event())
        except BaseException:
            shutil.rmtree(batch, ignore_errors=True)
            raise
        source = _target_path(folder, "/" + title["id"])
        return checked, skipped, len(matches), source
    finally:
        disk.close()


def cache_path():
    root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(root, "disk-reader", "catalog.json")


def load_cache(path=None):
    try:
        with open(path or cache_path(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_cache(cache, path=None):
    path = path or cache_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=1)


def fetch_catalog(store_ids, cache=None):
    """Titles for Store IDs: {id: {title, kind}}. Returns (results, had_network_error)."""
    cache = dict(cache or {})
    missing = [s for s in store_ids if s and s not in cache]
    failed = False
    for i in range(0, len(missing), 15):
        url = CATALOG_URL % ",".join(missing[i:i + 15])
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "disk-reader"})
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.load(r)
        except (OSError, ValueError):
            failed = True
            continue
        for p in data.get("Products", []):
            local = (p.get("LocalizedProperties") or [{}])[0]
            cache[p.get("ProductId", "")] = {"title": local.get("ProductTitle", ""),
                                             "kind": p.get("ProductKind", "")}
    return cache, failed


def clean_title(title):
    return re.sub(r"\s+", " ", re.sub("[®™]", "", title)).strip()


def apply_catalog(model, catalog):
    """Fill in catalog titles and types. Titles it doesn't know keep their fallback."""
    for t in model["titles"]:
        hit = catalog.get(t["store"])
        if hit and hit.get("title"):
            t["title"] = clean_title(hit["title"])
            t["title_source"] = "catalog"
            t["kind"] = KIND_LABELS.get(hit.get("kind"), t["kind"])
    model["titles"].sort(key=lambda t: -(t["size"] + t["pls"]))
    return model


def totals(model):
    """Bytes and counts per title type, plus local data, for the summary and capacity bar."""
    out = {"counts": {}, "installed": 0, "local": 0}
    for t in model["titles"]:
        out["counts"][t["kind"]] = out["counts"].get(t["kind"], 0) + 1
        out["installed"] += t["size"]
        out["local"] += t["pls"]
    return out
