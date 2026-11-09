"""The visibility split: no file list without the reader, names with it, bodies only when plaintext."""
import json
import unittest

import visibility
import xbox_card

GUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def xvs(package="Pub.Game_1.2.3.0_neutral__abc_xs.xvc"):
    doc = {"Request": {"StoreId": "9TEST", "Sources": {"ForegroundCrdPaths": ["http://x/y/" + package]}}}
    return json.dumps(doc).encode("utf-16-le")


def file(path, size=16, is_dir=False):
    return {"path": path, "is_dir": is_dir, "size": size, "created": "2024-01-01", "modified": "2024-01-02"}


def sample_model():
    files = [file("/" + GUID, 32), file("/%s.xvs" % GUID), file("/%s.xct" % GUID),
             file("/LastConsole", 16), file("/$MFT", 100), file("/PLS", is_dir=True)]
    model = xbox_card.build_model(files, {GUID: xvs()})
    model["boot"] = b"\x00\x00\x00NTFS    " + b"\x00" * 501
    title = next(t for t in model["titles"] if t["id"] == GUID)
    title["xvd"] = {"is_xvd": True, "encrypted": True, "cleartext_end": 0x7000}
    return model


class BootVisibility(unittest.TestCase):
    def test_blank_jump_hides_the_file_list_from_windows(self):
        boot = b"\x00\x00\x00NTFS    "
        seen = visibility.boot_visibility(boot)
        self.assertTrue(seen["ntfs_name_present"])
        self.assertFalse(seen["boot_jump_present"])
        self.assertIn("Windows shows no files", seen["without_reader"])
        self.assertIn("lists the file table", seen["with_reader"])

    def test_normal_jump_means_windows_may_show_the_names(self):
        boot = b"\xeb\x52\x90NTFS    "
        seen = visibility.boot_visibility(boot)
        self.assertTrue(seen["boot_jump_present"])
        self.assertIn("Windows may mount", seen["without_reader"])

    def test_missing_ntfs_name_stops_the_reader_too(self):
        seen = visibility.boot_visibility(b"\xeb\x52\x90" + b"MSDOS5.0")
        self.assertFalse(seen["ntfs_name_present"])
        self.assertIn("no NTFS name", seen["without_reader"])
        self.assertIn("stops here", seen["with_reader"])

    def test_missing_boot_sector_stays_unknown(self):
        seen = visibility.boot_visibility(None)
        self.assertIsNone(seen["ntfs_name_present"])
        self.assertIn("unknown", seen["without_reader"])


class FileVisibility(unittest.TestCase):
    def test_plaintext_records_are_fully_visible(self):
        model = sample_model()
        self.assertEqual(visibility.file_line(model, file("/%s.xvs" % GUID))[0], visibility.BODY)
        self.assertEqual(visibility.file_line(model, file("/LastConsole"))[0], visibility.BODY)

    def test_container_stops_at_the_header(self):
        model = sample_model()
        layer, sentence = visibility.file_line(model, file("/" + GUID, 32))
        self.assertEqual(layer, visibility.HEADER)
        self.assertIn("protected", sentence)
        self.assertIn("28672", sentence)  # 0x7000

    def test_undocumented_and_bookkeeping_files_stay_at_the_name(self):
        model = sample_model()
        self.assertEqual(visibility.file_line(model, file("/%s.xct" % GUID))[0], visibility.NAME)
        self.assertEqual(visibility.file_line(model, file("/$MFT", 100))[0], visibility.NAME)
        self.assertEqual(visibility.file_line(model, file("/PLS", is_dir=True))[0], visibility.NAME)

    def test_container_without_a_header_does_not_pretend_to_show_the_body(self):
        model = sample_model()
        for title in model["titles"]:
            title["xvd"] = None
        layer, sentence = visibility.file_line(model, file("/" + GUID, 32))
        self.assertEqual(layer, visibility.NAME)
        self.assertIn("No XVD header", sentence)

    def test_report_counts_the_three_layers(self):
        text = visibility.report_text(sample_model())
        self.assertIn("Windows shows no files", text)
        self.assertIn("2 of those files are plaintext", text)
        self.assertIn("1 show a header only", text)
        self.assertIn("2 show a name and size only", text)
        self.assertIn("1 folder", text)


if __name__ == "__main__":
    unittest.main()
