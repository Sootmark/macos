"""Writes btm.tsv: the background items files given read with Python's own
plistlib, an NSKeyedArchiver resolver and a bookmark reader written here
after libyal's dtformats description (independently of this crate): one
line per item, in file order, `\\N` for what it lacks:

file, record fields (user, uuid, name, identifier, url, executablePath,
bundleIdentifier, teamIdentifier, developerName, container, type,
disposition), bookmark fields (display name, target path, target creation
time and volume creation time in microseconds since 1970, volume name,
mount point, flags masked by those valid).

Run from tests/fixtures:
python3 -I ../oracle/gen_btm.py FILE... > ../oracle/btm.tsv
"""

import plistlib
import struct
import sys

COCOA_EPOCH = 978307200
# An item record's fields after its user, uuid and url (which comes third).
RECORD = (
    "name",
    "identifier",
    "executablePath",
    "bundleIdentifier",
    "teamIdentifier",
    "developerName",
    "container",
    "type",
    "disposition",
)


def uid(value):
    if isinstance(value, plistlib.UID):
        return value.data
    if isinstance(value, dict) and set(value) == {"CF$UID"}:
        return value["CF$UID"]
    return None


class Archive:
    def __init__(self, data):
        plist = plistlib.loads(data)
        self.objects = plist["$objects"]
        self.top = plist["$top"]

    def get(self, value, seen=()):
        """value, its references followed, collections and strings plain."""
        index = uid(value)
        if index is not None:
            if index in seen:
                return None
            target = self.objects[index]
            return None if target == "$null" else self.get(target, seen + (index,))
        if isinstance(value, dict) and "$class" in value:
            name = self.objects[uid(value["$class"])]["$classname"]
            if "NS.keys" in value:
                keys = [self.get(k, seen) for k in value["NS.keys"]]
                return dict(zip(keys, [self.get(v, seen) for v in value["NS.objects"]]))
            if "NS.objects" in value:
                return [self.get(v, seen) for v in value["NS.objects"]]
            if name in ("NSString", "NSMutableString"):
                return self.get(value["NS.string"], seen)
            if name in ("NSData", "NSMutableData"):
                return self.get(value["NS.data"], seen)
            fields = {k: v for k, v in value.items() if k != "$class"}
            fields["$classname"] = name
            fields["$seen"] = seen
            return fields
        return value

    def field(self, obj, key):
        return self.get(obj.get(key), obj.get("$seen", ())) if obj else None


def records(data, at):
    size, kind = struct.unpack_from("<II", data, at)
    return kind, data[at + 8 : at + 8 + size]


def bookmark(data):
    assert data[:4] in (b"book", b"alis")
    (area,) = struct.unpack_from("<I", data, 12)
    (toc,) = struct.unpack_from("<I", data, area)
    toc += area
    (count,) = struct.unpack_from("<I", data, toc + 16)
    out = {}
    for n in range(count):
        tag, offset = struct.unpack_from("<II", data, toc + 20 + n * 12)
        kind, value = records(data, area + offset)
        if tag == 0x1004:
            parts = struct.unpack(f"<{len(value) // 4}I", value)
            out["path"] = "/".join(records(data, area + p)[1].decode() for p in parts)
        elif tag in (0x1040, 0x2013):
            (seconds,) = struct.unpack(">d", value[:8])
            out[tag] = str(round((seconds + COCOA_EPOCH) * 1_000_000))
        elif tag in (0x2002, 0x2010, 0xF017):
            out[tag] = value.decode()
        elif tag == 0x2020:
            flags, valid = struct.unpack_from("<QQ", value)
            out[tag] = str(flags & valid)
    if "path" in out:
        out["path"] = out.get(0x2002, "") + out["path"]
    return [out.get(k) for k in (0xF017, "path", 0x1040, 0x2013, 0x2010, 0x2002, 0x2020)]


def bookmark_bytes(archive, obj, key):
    value = archive.field(obj, key)
    if isinstance(value, dict):
        value = archive.field(value, "data")
    return value if isinstance(value, bytes) else None


def items(archive):
    root = archive.get(archive.top.get("root")) or {}
    background = archive.field(root, "backgroundItems") if root else None
    if background:
        for container in archive.field(background, "allContainers"):
            found = bookmark_bytes(archive, container, "bookmark")
            if found:
                yield [None] * 12, bookmark(found)
            internal = archive.field(container, "internalItems")
            if isinstance(internal, list):
                members = internal
            else:  # an NSHashTable: $1, $2, … after its options in $0
                slots = sorted(int(k[1:]) for k in internal if k[1:].isdigit() and k != "$0")
                members = [archive.field(internal, f"${n}") for n in slots]
            for item in filter(None, members):
                found = bookmark_bytes(archive, item, "bookmark")
                if found:
                    yield [None] * 12, bookmark(found)
        return
    store = archive.get(archive.top["store"])
    users = archive.field(store, "itemsByUserIdentifier")
    for user, list_ in users.items():
        for item in list_:
            uuid = archive.field(item, "uuid")
            raw = archive.field(uuid, "NS.uuidbytes") if uuid else None
            text = raw.hex().upper() if raw else None
            uuid = text and "-".join([text[:8], text[8:12], text[12:16], text[16:20], text[20:]])
            url = archive.field(item, "url")
            url = archive.field(url, "NS.relative") if url else None
            fields = [archive.field(item, k) for k in RECORD]
            record = [user, uuid] + fields[:2] + [url] + fields[2:]
            found = bookmark_bytes(archive, item, "bookmark")
            yield record, bookmark(found) if found else [None] * 7


for name in sys.argv[1:]:
    with open(name, "rb") as file:
        archive = Archive(file.read())
    for record, marks in items(archive):
        cells = [name] + ["\\N" if c is None else str(c) for c in record + marks]
        print("\t".join(cells))
