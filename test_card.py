"""Tests that need no disk and no admin rights. Run: python -m unittest test_card"""
import hashlib
import io
import json
import os
import struct
import tempfile
import threading
import unittest
import uuid

import ntfs_security
import xbox_card
from ntfs_reader import Ntfs, parse_record

GUID = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
BUILD = "11111111-2222-3333-4444-555555555555"


class FakeDisk:
    """Clusters of 16 bytes where every byte equals its cluster number plus one."""

    def read(self, offset, length):
        return bytes((offset + i) // 16 + 1 for i in range(length))


def volume():
    vol = Ntfs.__new__(Ntfs)
    vol.disk, vol.offset, vol.cluster = FakeDisk(), 0, 16
    return vol


def nonresident(size, init, runs, flags=0):
    return {"data": {"size": size, "init": init, "flags": flags, "resident": False,
                     "content": None, "runs": runs},
            "names": [{"name": "x", "parent": 5, "namespace": 1}], "is_dir": False}


def read(vol, rec):
    sink = io.BytesIO()
    vol.read_file(rec, sink)
    return sink.getvalue()


class ReadFile(unittest.TestCase):
    def test_follows_fragmented_runs(self):
        out = read(volume(), nonresident(32, 32, [(1, 5), (1, 2)]))
        self.assertEqual(out, bytes([6]) * 16 + bytes([3]) * 16)

    def test_sparse_runs_are_zeros(self):
        self.assertEqual(read(volume(), nonresident(32, 32, [(1, None), (1, 0)])),
                         bytes(16) + bytes([1]) * 16)

    def test_bytes_past_valid_data_are_zeros(self):
        self.assertEqual(read(volume(), nonresident(32, 20, [(2, 0)])),
                         bytes([1]) * 16 + bytes([2]) * 4 + bytes(12))

    def test_truncates_to_file_size(self):
        self.assertEqual(len(read(volume(), nonresident(20, 20, [(2, 0)]))), 20)

    def test_short_runlist_fails(self):
        with self.assertRaises(ValueError):
            read(volume(), nonresident(32, 32, [(1, 0)]))

    def test_refuses_compressed(self):
        with self.assertRaises(ValueError):
            read(volume(), nonresident(32, 32, [(2, 0)], flags=1))


def xvs(store="9TEST", package="Pub.Game_1.2.3.0_neutral__abc_xs.xvc"):
    doc = {"Request": {"StoreId": store, "Sources": {"ForegroundCrdPaths": ["http://x/y/" + package]}},
           "Status": {"Source": {"Current": {"BuildId": BUILD, "Platform": "Gen9GameCore"}}}}
    return json.dumps(doc).encode("utf-16-le")


def file(path, size=16, is_dir=False):
    return {"path": path, "is_dir": is_dir, "size": size, "created": "2024-01-01", "modified": "2024-01-02"}


def model():
    files = [file("/" + GUID, 32), file("/%s.xvs" % GUID), file("/%s.xct" % GUID), file("/%s.xvi" % GUID),
             file("/%s.pfm" % BUILD.lower()), file("/PLS/u/%s-PLS" % GUID), file("/other.pfm"),
             file("/PLS/u/99999999-9999-9999-9999-999999999999-PLS", 64),
             file("/99999999-AAAA-AAAA-AAAA-AAAAAAAAAAAA")]
    return xbox_card.build_model(files, {GUID: xvs()}, 1000, 500)


class Model(unittest.TestCase):
    def test_links_container_metadata_and_local_data(self):
        t = next(t for t in model()["titles"] if t["id"] == GUID)
        self.assertEqual((t["kind"], t["store"], t["version"], t["size"], t["pls"]),
                         ("Game", "9TEST", "1.2.3.0", 32, 16))

    def test_unknowns_stay_visible(self):
        unknown = [t for t in model()["titles"] if t["kind"] == xbox_card.UNKNOWN]
        self.assertEqual(sorted(t["title"] for t in unknown),
                         ["Local data with no installed title", "Unidentified container"])

    def test_catalog_marks_add_ons_and_strips_symbols(self):
        m = model()
        xbox_card.apply_catalog(m, {"9TEST": {"title": "Game™ Pack®", "kind": "Durable"}})
        t = next(t for t in m["titles"] if t["id"] == GUID)
        self.assertEqual((t["title"], t["kind"]), ("Game Pack", "Add-on"))

    def test_package_includes_every_part_and_nothing_else(self):
        m = model()
        t = next(t for t in m["titles"] if t["id"] == GUID)
        paths = {f["path"] for f in xbox_card.package_files(m, t)}
        self.assertEqual(len(paths), 6)
        self.assertNotIn("/other.pfm", paths)
        self.assertEqual(xbox_card.package_size(m, t), 32 + 16 * 5)


class FileLabels(unittest.TestCase):
    def labels(self, extra=()):
        m = model()
        m["files"].extend(extra)
        return xbox_card.file_labels(m)

    def test_id_named_files_show_their_title(self):
        m = model()
        xbox_card.apply_catalog(m, {"9TEST": {"title": "Real Game", "kind": "Game"}})
        labels = xbox_card.file_labels(m)
        self.assertEqual(labels["/" + GUID], ("Real Game", "Game package"))
        self.assertEqual(labels["/%s.xvs" % GUID], ("Real Game", "Install record"))
        self.assertEqual(labels["/%s.pfm" % BUILD.lower()], ("Real Game", "Package build file (.pfm)"))
        self.assertEqual(labels["/PLS/u/%s-PLS" % GUID], ("Real Game", "Local data"))

    def test_app_container_is_not_mistaken_for_a_sidecar(self):
        m = xbox_card.build_model([file("/Pub.App_abc.UW9"), file("/Pub.App_abc.UW9.xvs")],
                                  {"Pub.App_abc.UW9": json.dumps({"Request": {"StoreId": "9APP"}}).encode("utf-16-le")})
        labels = xbox_card.file_labels(m)
        self.assertEqual(labels["/Pub.App_abc.UW9"][1], "App package")
        self.assertEqual(labels["/Pub.App_abc.UW9.xvs"][1], "Install record")

    def test_unknowns_are_labelled_as_unknown_rather_than_guessed(self):
        labels = self.labels()
        self.assertEqual(labels["/other.pfm"], ("Not linked to a title", "Unrecognized file"))
        self.assertEqual(labels["/99999999-AAAA-AAAA-AAAA-AAAAAAAAAAAA"],
                         ("Unidentified container", "Unidentified package"))
        self.assertEqual(labels["/PLS/u/99999999-9999-9999-9999-999999999999-PLS"],
                         ("Local data with no installed title", "Local data"))

    def test_system_and_card_files(self):
        labels = self.labels([file("/$MFT"), file("/LastConsole"), file("/PLS", is_dir=True),
                              file("/$Extend", is_dir=True)])
        self.assertEqual(labels["/$MFT"], ("Card filesystem", "NTFS system file"))
        self.assertEqual(labels["/$Extend"], ("Card filesystem", "NTFS system folder"))
        self.assertEqual(labels["/LastConsole"], ("Xbox card", "Last-used console record"))
        self.assertEqual(labels["/PLS"], ("Xbox card", "Local data folder"))


class Export(unittest.TestCase):
    def setUp(self):
        self.m = model()
        self.t = next(t for t in self.m["titles"] if t["id"] == GUID)
        self.records = {}
        for i, f in enumerate(self.m["files"], start=100):
            rec = nonresident(f["size"], f["size"], [(f["size"] // 16, i)])
            parts = f["path"].strip("/").split("/")
            parent = 5
            if len(parts) > 1:  # register folders so full_path can resolve nested files
                for j, part in enumerate(parts[:-1]):
                    num = 10 + j
                    self.records[num] = {"data": None, "is_dir": True,
                                         "names": [{"name": part, "parent": parent, "namespace": 1}]}
                    parent = num
            rec["names"] = [{"name": parts[-1], "parent": parent, "namespace": 1}]
            self.records[i] = rec
        self.vol = volume()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def export(self, cancel=None, sink=lambda n: None):
        return xbox_card.export_title(self.vol, self.records, self.m, self.t, self.tmp.name, sink,
                                      cancel or threading.Event())

    def test_copies_all_parts_with_matching_hashes(self):
        folder = self.export()
        with open(os.path.join(folder, "manifest.json"), encoding="utf-8") as manifest_file:
            manifest = json.load(manifest_file)
        self.assertEqual(len(manifest["files"]), 6)
        for e in manifest["files"]:
            with open(os.path.join(folder, *e["path"].strip("/").split("/")), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), e["sha256"])

    def test_never_overwrites_an_earlier_copy(self):
        folder = self.export()
        keep = os.path.join(folder, "keep.txt")
        open(keep, "w").close()
        with self.assertRaises(FileExistsError):
            self.export()
        self.assertTrue(os.path.exists(keep))

    def test_cancel_removes_the_unfinished_copy(self):
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(xbox_card.Cancelled):
            self.export(cancel)
        self.assertEqual(os.listdir(self.tmp.name), [])

    def test_read_error_removes_the_unfinished_copy(self):
        self.vol.disk.read = lambda *a: (_ for _ in ()).throw(OSError("unplugged"))
        with self.assertRaises(OSError):
            self.export()
        self.assertEqual(os.listdir(self.tmp.name), [])


class CopyAnyFiles(unittest.TestCase):
    setUp = Export.setUp

    def copy(self, files, cancel=None, sink=lambda n: None):
        folder = os.path.join(self.tmp.name, "out")
        return xbox_card.copy_files(self.vol, self.records, files, folder, sink, cancel or threading.Event())

    def plain_files(self):
        return [f for f in self.m["files"] if not f["is_dir"]]

    def test_copies_every_file_including_ones_with_no_title(self):
        r = self.copy(self.plain_files())
        self.assertTrue(r["complete"])
        self.assertEqual(len(r["copied"]), len(self.plain_files()))
        self.assertTrue(os.path.exists(os.path.join(r["folder"], "other.pfm")))
        self.assertTrue(os.path.exists(os.path.join(r["folder"], "PLS", "u", "%s-PLS" % GUID)))
        for e in r["copied"]:
            with open(os.path.join(r["folder"], *e["path"].strip("/").split("/")), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), e["sha256"])
        with open(os.path.join(r["folder"], xbox_card.MANIFEST_NAME), encoding="utf-8") as f:
            self.assertTrue(json.load(f)["complete"])

    def test_one_bad_file_does_not_lose_the_rest(self):
        files = self.plain_files()
        bad = next(n for n, rec in self.records.items() if rec["names"][0]["name"] == "other.pfm")
        self.records[bad]["data"]["flags"] = 1  # compressed, which read_file refuses
        r = self.copy(files)
        self.assertFalse(r["complete"])
        self.assertEqual([e["path"] for e in r["failed"]], ["/other.pfm"])
        self.assertEqual(len(r["copied"]), len(files) - 1)
        self.assertFalse(os.path.exists(os.path.join(r["folder"], "other.pfm.part")))

    def test_cancel_keeps_verified_files_and_removes_the_partial_one(self):
        files, cancel, seen = self.plain_files(), threading.Event(), [0]
        first = files[0]["size"] * 2

        def sink(n):
            seen[0] += n
            if seen[0] > first:
                cancel.set()
        r = self.copy(files, cancel, sink)
        self.assertTrue(r["cancelled"])
        self.assertEqual([e["path"] for e in r["copied"]], [files[0]["path"]])
        names = [n for _, _, ns in os.walk(r["folder"]) for n in ns]
        self.assertFalse([n for n in names if n.endswith(".part")])

    def test_file_with_no_data_becomes_an_empty_file(self):
        rec = {"data": None, "is_dir": False, "names": [{"name": "$Quota", "parent": 5, "namespace": 1}]}
        self.records[900] = rec
        r = self.copy([file("/$Quota", 0)])
        self.assertTrue(r["complete"])
        self.assertEqual(os.path.getsize(os.path.join(r["folder"], "$Quota")), 0)

    def test_notes_named_streams_it_did_not_copy(self):
        f = self.plain_files()[0]
        rec = next(r for r in self.records.values() if r["names"][0]["name"] == f["path"].rsplit("/", 1)[-1])
        rec["streams"] = 2
        self.assertEqual(self.copy([f])["copied"][0]["named_streams_not_copied"], 2)

    def test_refuses_names_that_escape_the_folder(self):
        for name in ("/../evil", "/a/../../evil", "/C:evil"):
            with self.assertRaises(ValueError):
                xbox_card._target_path(self.tmp.name, name)

    def test_selecting_a_folder_means_everything_inside_it(self):
        chosen = [file("/PLS", is_dir=True), file("/other.pfm")]
        paths = {f["path"] for f in xbox_card.expand_selection(self.m, chosen)}
        self.assertIn("/other.pfm", paths)
        self.assertIn("/PLS/u/%s-PLS" % GUID, paths)
        self.assertNotIn("/" + GUID, paths)


def sid(text):
    parts = [int(p) for p in text.split("-")[1:]]
    subs = parts[2:]
    return (bytes([parts[0], len(subs)]) + parts[1].to_bytes(6, "big")
            + b"".join(s.to_bytes(4, "little") for s in subs))


def ace(kind, mask, account, flags=0):
    body = struct.pack("<I", mask) + sid(account)
    return struct.pack("<BBH", kind, flags, 4 + len(body)) + body


def descriptor(owner="S-1-5-18", aces=(), dacl=True):
    own = sid(owner)
    head_size = 20
    if not dacl:
        return struct.pack("<BBHIIII", 1, 0, 0x8000, head_size, 0, 0, 0) + own
    acl_body = b"".join(aces)
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(acl_body), len(aces), 0) + acl_body
    return struct.pack("<BBHIIII", 1, 0, 0x8004, head_size + len(acl), 0, 0, head_size) + acl + own


def sds_entry(sec_id, desc, offset):
    length = 20 + len(desc)
    raw = struct.pack("<IIQI", 0, sec_id, offset, length) + desc
    return raw + bytes(((length + 15) & ~15) - length)


CONSOLE_ID = "57BF1FC4-1D4F-11EA-80FB-806E6F6E6963"


def console_record(guid=CONSOLE_ID, count=1):
    head = struct.pack("<IIII", 1, 0, count, 64).ljust(64, b"\0")
    return (head + uuid.UUID(guid).bytes_le + struct.pack("<I", 1)).ljust(4096, b"\0")


class CardInfo(unittest.TestCase):
    def info(self, **records):
        m = xbox_card.build_model([file("/ConsoleAssociations"), file("/LastConsole")], {})
        m["card_records"] = records
        return xbox_card.card_info_text(m)

    def test_decodes_console_and_matches_last_used(self):
        text = self.info(consoleassociations=console_record(), lastconsole=uuid.UUID(CONSOLE_ID).bytes_le)
        self.assertIn("Consoles listed: 1", text)
        self.assertIn(CONSOLE_ID, text)
        self.assertIn("Date inside ID:  2019-12-13", text)
        self.assertIn("Same as last-used console: yes", text)

    def test_reports_a_different_last_used_console(self):
        other = uuid.UUID("11111111-2222-3333-4444-555555555555").bytes_le
        self.assertIn("Same as last-used console: no", self.info(consoleassociations=console_record(), lastconsole=other))

    def test_several_consoles_are_not_overclaimed(self):
        self.assertIn("Only the first ID is decoded", self.info(consoleassociations=console_record(count=2)))

    def test_short_or_invalid_records_do_not_crash(self):
        self.assertIn("too short", self.info(consoleassociations=b"\x01"))
        self.assertIn("outside the file", self.info(consoleassociations=struct.pack("<IIII", 1, 0, 1, 9000)))
        self.assertIn("not readable", self.info(lastconsole=b"\x01\x02"))
        self.assertIn("Couldn't decode this file", self.info(**{"storagestate.json": b"\xff\xfe\x00\xd8"}))

    def test_card_id_decodes_from_utf16_json(self):
        doc = '{"Version":2,"DeviceId":"d621dae5-8e6f-11eb-9cc0-806e6f6e6963"}'.encode("utf-16-le")
        self.assertIn("DeviceId: D621DAE5-8E6F-11EB-9CC0-806E6F6E6963", self.info(**{"storagestate.json": doc}))

    def test_disk_without_records_says_so(self):
        self.assertEqual(self.info(), "This disk has no Xbox card records.")

    def test_interpretation_is_labelled(self):
        self.assertIn("Interpreted", self.info(consoleassociations=console_record()))


def xvd_header(flags=0x41, fmt=3, payload=3128307712, vduid=GUID, uduid=None, body_at=0x7000, total=0x20000):
    import xvd as _xvd
    h = bytearray(total)
    h[0x200:0x208] = b"msft-xvd"
    struct.pack_into("<I", h, 0x208, flags)
    struct.pack_into("<I", h, 0x20C, fmt)
    struct.pack_into("<Q", h, 0x210, 132000000000000000)  # a plausible FILETIME
    struct.pack_into("<Q", h, 0x218, payload)
    h[0x220:0x230] = uuid.UUID(vduid).bytes_le
    h[0x230:0x240] = uuid.UUID(uduid or vduid).bytes_le
    import os as _os
    h[body_at:body_at + 0x2000] = _os.urandom(0x2000)  # high-entropy "encrypted" body
    return bytes(h)


class XvdHeaderParse(unittest.TestCase):
    def test_parses_confirmed_fields(self):
        import xvd
        x = xvd.parse_header(xvd_header(), 3242708992)
        self.assertTrue(x["is_xvd"])
        self.assertEqual(x["content_id"], GUID)
        self.assertEqual(x["format_version"], 3)
        self.assertEqual(x["payload_bytes"], 3128307712)
        self.assertEqual(x["overhead_bytes"], 3242708992 - 3128307712)
        self.assertTrue(x["encrypted"])          # flag 0x41 has no "encryption disabled" bit
        self.assertTrue(x["read_only"])

    def test_encryption_disabled_flag(self):
        import xvd
        self.assertFalse(xvd.parse_header(xvd_header(flags=0x43), 1)["encrypted"])

    def test_locates_cleartext_boundary(self):
        import xvd
        self.assertEqual(xvd.parse_header(xvd_header(body_at=0x7000), 1)["cleartext_end"], 0x7000)

    def test_rejects_non_xvd(self):
        import xvd
        self.assertFalse(xvd.parse_header(b"\0" * 0x300, 1)["is_xvd"])
        self.assertFalse(xvd.parse_header(b"\0" * 16, 1)["is_xvd"])


class ReadPrefix(unittest.TestCase):
    def test_reads_only_the_requested_prefix(self):
        vol = volume()
        rec = nonresident(64, 64, [(2, 5), (2, 9)])  # 4 clusters of 16 bytes
        self.assertEqual(vol.read_prefix(rec, 20), bytes([6]) * 16 + bytes([7]) * 4)

    def test_resident_prefix(self):
        vol = volume()
        rec = {"data": {"size": 8, "init": 8, "flags": 0, "resident": True, "content": b"ABCDEFGH", "runs": []},
               "names": [{"name": "x", "parent": 5, "namespace": 1}], "is_dir": False}
        self.assertEqual(vol.read_prefix(rec, 3), b"ABC")


class Permissions(unittest.TestCase):
    def test_translates_accounts_and_access(self):
        rule = ntfs_security.parse_descriptor(descriptor(aces=[
            ace(0, 0x1F01FF, "S-1-5-18"), ace(0, 0x1F01FF, "S-1-5-32-544"), ace(0, 0x120089, "S-1-1-0")]))
        self.assertEqual(ntfs_security.summary(rule), "Full control: SYSTEM, Administrators; Read: Everyone")
        self.assertEqual(rule["owner"], "S-1-5-18")

    def test_deny_is_shown_as_deny(self):
        rule = ntfs_security.parse_descriptor(descriptor(aces=[ace(1, 0x120116, "S-1-5-32-545")]))
        self.assertEqual(ntfs_security.summary(rule), "Deny Write: Users")

    def test_unknown_accounts_and_masks_are_not_guessed(self):
        self.assertEqual(ntfs_security.account_name("S-1-9-9"), "Unrecognized account")
        self.assertEqual(ntfs_security.account_name("S-1-5-21-1-2-3-1001"), "Device or domain account")
        self.assertEqual(ntfs_security.access_name(0x12345), "Custom access (0x00012345)")

    def test_missing_and_empty_lists_are_explained(self):
        self.assertIn("wouldn't restrict", ntfs_security.summary(ntfs_security.parse_descriptor(descriptor(dacl=False))))
        self.assertIn("refuse", ntfs_security.summary(ntfs_security.parse_descriptor(descriptor())))

    def test_inherit_only_entries_are_marked_not_summarized(self):
        rule = ntfs_security.parse_descriptor(descriptor(aces=[
            ace(0, 0x120089, "S-1-1-0"), ace(0, 0x1F01FF, "S-1-3-0", flags=0x08)]))
        self.assertEqual(ntfs_security.summary(rule), "Read: Everyone")
        self.assertIn("for new items only", ntfs_security.describe(rule))

    def test_stream_reads_every_block_and_skips_the_mirror(self):
        d1, d2 = descriptor(aces=[ace(0, 0x120089, "S-1-1-0")]), descriptor(owner="S-1-5-32-544")
        first = sds_entry(256, d1, 0)
        second = sds_entry(257, d2, len(first))
        block = (first + second).ljust(ntfs_security.BLOCK, b"\0")
        mirror = sds_entry(999, d1, ntfs_security.BLOCK).ljust(ntfs_security.BLOCK, b"\0")
        third = sds_entry(258, d2, ntfs_security.BLOCK * 2)
        rules = ntfs_security.parse_sds(block + mirror + third)
        self.assertEqual(sorted(rules), [256, 257, 258])

    def test_damaged_rule_is_reported_and_others_survive(self):
        bad = struct.pack("<BBHIIII", 1, 0, 0x8004, 9999, 0, 0, 0)
        first = sds_entry(256, bad, 0)
        rules = ntfs_security.parse_sds(first + sds_entry(257, descriptor(), len(first)))
        self.assertIn("Couldn't decode", rules[256]["note"])
        self.assertIn(257, rules)

    def test_files_link_to_their_rule(self):
        m = xbox_card.build_model([dict(file("/a"), security_id=256), dict(file("/b"), security_id=256),
                                   dict(file("/c"), security_id=500)], {})
        m["security"] = {256: ntfs_security.parse_descriptor(descriptor(aces=[ace(0, 0x120089, "S-1-1-0")]))}
        self.assertEqual(xbox_card.permission_rows(m)[0]["files"], ["/a", "/b"])
        self.assertIn("Allow Read: Everyone", xbox_card.file_permission(m, m["files"][0]))
        self.assertIn("No permission rule", xbox_card.file_permission(m, m["files"][2]))

    def test_mft_record_gives_security_id_and_named_stream(self):
        si = bytes(52) + struct.pack("<I", 321) + bytes(16)
        si_attr = struct.pack("<IIBBHHH", 0x10, 24 + len(si), 0, 0, 0, 0, 0) + struct.pack("<IH", len(si), 24) + b"\0\0" + si
        name = "$SDS".encode("utf-16-le")
        content = b"rules!"
        body = name + content
        ds = struct.pack("<IIBBHHH", 0x80, (24 + len(body) + 7) & ~7, 0, 4, 24, 0, 0) + struct.pack("<IH", len(content), 32) + b"\0\0" + body
        ds = ds.ljust((24 + len(body) + 7) & ~7, b"\0")
        rec = bytearray(1024)
        rec[:4] = b"FILE"
        struct.pack_into("<HH", rec, 4, 48, 1)  # no fixups to apply
        struct.pack_into("<H", rec, 20, 56)
        struct.pack_into("<H", rec, 22, 1)
        attrs = si_attr + ds + struct.pack("<I", 0xFFFFFFFF) + bytes(12)
        rec[56:56 + len(attrs)] = attrs
        parsed = parse_record(bytes(rec), keep_data=True)
        self.assertEqual(parsed["security_id"], 321)
        self.assertEqual(parsed["named"]["$SDS"]["content"], b"rules!")
        self.assertEqual(parsed["streams"], 1)


if __name__ == "__main__":
    unittest.main()
