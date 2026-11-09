"""Decode NTFS permission rules from the $Secure:$SDS stream into plain words. Read-only.

Security-descriptor layout and the well-known SID names follow Microsoft's
documentation. Names for SID families are labels for display, not account lookups.
"""
import struct

BLOCK = 0x40000  # $SDS alternates 256 KB of rules with a 256 KB mirror of them

WELL_KNOWN = {
    "S-1-1-0": "Everyone",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-5-7": "Anonymous",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "SYSTEM",
    "S-1-5-19": "Local Service",
    "S-1-5-20": "Network Service",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-15-2-1": "All App Packages",
    "S-1-15-2-2": "All Restricted App Packages",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": "TrustedInstaller",
}
SID_FAMILIES = (("S-1-5-21-", "Device or domain account"), ("S-1-15-2-", "App package"),
                ("S-1-15-3-", "App capability"), ("S-1-5-80-", "Windows service"),
                ("S-1-5-83-", "Virtual machine"), ("S-1-16-", "Integrity level"))
ACCESS = {0x1F01FF: "Full control", 0x1301BF: "Modify", 0x1200A9: "Read and run", 0x120089: "Read",
          0x120116: "Write", 0x10000000: "Full control", 0xE0000000: "Full control", 0x80000000: "Read",
          0x40000000: "Write", 0x20000000: "Run", 0xA0000000: "Read and run", 0xC0000000: "Read and write"}
ACE_KINDS = {0: "Allow", 1: "Deny"}
SE_DACL_PRESENT = 0x0004


def parse_sid(b, off):
    """Text form of a SID, or a ValueError if it runs off the end of the buffer."""
    if off < 0 or off + 8 > len(b):
        raise ValueError("SID outside the rule")
    count = b[off + 1]
    if off + 8 + count * 4 > len(b):
        raise ValueError("truncated SID")
    authority = int.from_bytes(b[off + 2:off + 8], "big")
    subs = struct.unpack("<%dI" % count, b[off + 8:off + 8 + count * 4])
    return "S-%d-%d" % (b[off], authority) + "".join("-%d" % s for s in subs)


def account_name(sid):
    """A readable name. Unrecognized accounts keep their ID, since guessing would mislead."""
    if sid in WELL_KNOWN:
        return WELL_KNOWN[sid]
    for prefix, family in SID_FAMILIES:
        if sid.startswith(prefix):
            return family
    return "Unrecognized account"


def access_name(mask):
    return ACCESS.get(mask, "Custom access (0x%08X)" % mask)


def parse_descriptor(b):
    """One self-relative security descriptor to {owner, group, aces, note}."""
    if len(b) < 20:
        raise ValueError("rule too short")
    control, owner, group, _sacl, dacl = struct.unpack("<HIIII", b[2:20])
    rule = {"owner": parse_sid(b, owner) if owner else None, "group": parse_sid(b, group) if group else None,
            "aces": [], "note": ""}
    if not (control & SE_DACL_PRESENT) or not dacl:
        rule["note"] = "No permission list, so Windows wouldn't restrict access"
        return rule
    if dacl + 8 > len(b):
        raise ValueError("permission list outside the rule")
    count = struct.unpack("<H", b[dacl + 4:dacl + 6])[0]
    pos = dacl + 8
    for _ in range(count):
        if pos + 4 > len(b):
            raise ValueError("truncated permission list")
        kind, flags, size = struct.unpack("<BBH", b[pos:pos + 4])
        if size < 8 or pos + size > len(b):
            raise ValueError("bad permission entry")
        if kind in ACE_KINDS:
            mask = struct.unpack("<I", b[pos + 4:pos + 8])[0]
            rule["aces"].append({"kind": ACE_KINDS[kind], "sid": parse_sid(b, pos + 8),
                                 "access": access_name(mask), "inherit_only": bool(flags & 0x08)})
        else:
            rule["aces"].append({"kind": "Other (type %d)" % kind, "sid": "", "access": "Not decoded",
                                 "inherit_only": bool(flags & 0x08)})
        pos += size
    if not rule["aces"]:
        rule["note"] = "Empty permission list, so Windows would refuse access"
    return rule


def parse_sds(data):
    """Every rule in a $SDS stream, keyed by the ID that files refer to."""
    rules = {}
    start = 0
    while start < len(data):
        block = data[start:start + BLOCK]
        pos = 0
        while pos + 20 <= len(block):
            _hash, sec_id, offset, length = struct.unpack("<IIQI", block[pos:pos + 20])
            if not sec_id or length < 20 or offset != start + pos or pos + length > len(block):
                break  # the rest of this block is empty
            try:
                rules.setdefault(sec_id, parse_descriptor(block[pos + 20:pos + length]))
            except (ValueError, struct.error) as e:
                rules.setdefault(sec_id, {"owner": None, "group": None, "aces": [],
                                          "note": "Couldn't decode this rule: %s" % e})
            pos += (length + 15) & ~15
        start += BLOCK * 2
    return rules


def summary(rule):
    """One line such as 'Full control: SYSTEM, Administrators; Read: Everyone'."""
    groups = {}
    for ace in rule["aces"]:
        if ace["inherit_only"]:
            continue
        key = ace["access"] if ace["kind"] == "Allow" else "%s %s" % (ace["kind"], ace["access"])
        who = account_name(ace["sid"]) if ace["sid"] else "Unknown"
        names = groups.setdefault(key, [])
        if who not in names:
            names.append(who)
    text = "; ".join("%s: %s" % (k, ", ".join(v)) for k, v in groups.items())
    return text or rule["note"] or "Only applies to new items inside this folder"


def describe(rule):
    """Multi-line plain description for a details panel."""
    lines = []
    if rule["owner"]:
        lines.append("Owner: %s (%s)" % (account_name(rule["owner"]), rule["owner"]))
    if rule["note"]:
        lines.append(rule["note"])
    for ace in rule["aces"]:
        who = "%s (%s)" % (account_name(ace["sid"]), ace["sid"]) if ace["sid"] else "Unknown"
        tail = ", for new items only" if ace["inherit_only"] else ""
        lines.append("%s %s: %s%s" % (ace["kind"], ace["access"], who, tail))
    return "\n".join(lines)
