"""What a card shows with and without this reader.

Windows mounts a volume from its boot sector. This reader never mounts: it
looks for the NTFS name and walks the file table, including when the boot
jump has been blanked. Names and sizes come from that table. A few small
records are plaintext and are read in full. A container header is plaintext;
its body is not decoded.
"""
import os

import xbox_card

BODY = "body"
HEADER = "header"
NAME = "name"


def boot_visibility(boot):
    """How the boot sector decides whether Windows has a file list to show."""
    if not boot or len(boot) < 11:
        return {
            "ntfs_name_present": None,
            "boot_jump_present": None,
            "without_reader": "No boot sector was recorded with this model, so whether Windows would mount it is unknown.",
            "with_reader": "The names below are the file table this reader already walked.",
        }
    ntfs_name = boot[3:11] == b"NTFS    "
    jump_present = boot[0] in (0xEB, 0xE9)
    if not ntfs_name:
        return {
            "ntfs_name_present": False,
            "boot_jump_present": jump_present,
            "without_reader": "This boot sector has no NTFS name, so Windows has no volume to show.",
            "with_reader": "This reader also stops here. It only lists a volume whose boot sector says NTFS.",
        }
    if jump_present:
        return {
            "ntfs_name_present": True,
            "boot_jump_present": True,
            "without_reader": "The boot sector has a normal NTFS jump, so Windows may mount the volume and show these file names itself.",
            "with_reader": "This reader lists the same file table without mounting the volume.",
        }
    return {
        "ntfs_name_present": True,
        "boot_jump_present": False,
        "without_reader": "The NTFS name is intact and the boot jump is blank, so Windows shows no files.",
        "with_reader": "This reader ignores the blank jump and lists the file table anyway.",
    }


def _titles(model):
    return {t["id"].lower(): t for t in model.get("titles", [])}


def file_line(model, f, titles=None):
    """(layer, sentence) for one file the reader has already listed."""
    titles = _titles(model) if titles is None else titles
    path = f["path"]
    if f.get("is_dir"):
        return NAME, "Folder name only."
    low = path.lower()
    base = low.lstrip("/")
    ext = os.path.splitext(path)[1].lower()
    if base in xbox_card.CARD_FILES or (ext == ".xvs" and path.count("/") == 1):
        return BODY, "Visible in full. This is a small plaintext record, and the reader reads the whole file."
    title = titles.get(base) if xbox_card.CONTAINER.match(path) else None
    if title is not None and not f.get("is_dir"):
        header = title.get("xvd") or {}
        if header.get("is_xvd"):
            boundary = header.get("cleartext_end")
            where = " Cleartext ends at byte %d." % boundary if boundary else ""
            if header.get("encrypted"):
                return HEADER, (
                    "The file name and the XVD header are visible.%s The body is protected and is not decoded."
                    % where)
            return HEADER, (
                "The file name and the XVD header are visible.%s The reader does not decode the body." % where)
        return NAME, "The file name and size are visible. No XVD header was read, so nothing inside the file is shown."
    if path.startswith("/$"):
        return NAME, "NTFS bookkeeping. The reader uses it to list the card."
    return NAME, "The file name and size are visible. The reader does not interpret this body."


def report_text(model):
    """Short account of what is visible, for the card panel."""
    boot = boot_visibility(model.get("boot"))
    titles = _titles(model)
    counts = {BODY: 0, HEADER: 0, NAME: 0}
    folders = 0
    for f in model.get("files", []):
        if f.get("is_dir"):
            folders += 1
            continue
        layer, _sentence = file_line(model, f, titles)
        counts[layer] += 1
    files = sum(counts.values())
    folder_word = "folder" if folders == 1 else "folders"
    lines = [
        "WHAT YOU CAN SEE",
        "",
        "Without this reader",
        "  " + boot["without_reader"],
        "",
        "With this reader",
        "  " + boot["with_reader"],
        "  %d files and %d %s have a visible name and size." % (files, folders, folder_word),
        "  %d of those files are plaintext and are read in full." % counts[BODY],
        "  %d show a header only. Their bodies are not decoded." % counts[HEADER],
        "  %d show a name and size only." % counts[NAME],
    ]
    return "\n".join(lines)
