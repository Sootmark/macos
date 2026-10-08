"""plaso's Spotlight property list, Messages and keychain events (psort JSON
lines) as the TSVs tests/spotlight_prefs.rs, tests/messages.rs and
tests/keychain.rs compare: one line per event, sorted: its data type, which
time, the time in microseconds, and its values as key=value (newlines and
tabs escaped). A keychain item's ssgp_hash is left out: it is the item's
encrypted secret (its label, IV and ciphertext), which this crate never
reads.

Made with plaso 20260720 on the test files in a folder (in/), on Debian:

  docker run --rm -v "$PWD/in:/in:ro" -v "$PWD/out:/data" \
    log2timeline/plaso:20260720 log2timeline --status_view none -q \
    --parsers PARSERS --storage-file /data/out.plaso /in
  docker run --rm -v "$PWD/out:/data" log2timeline/plaso:20260720 \
    psort --status_view none -q -o json_line -w /data/out.jsonl /data/out.plaso
  python3 -I gen_events.py out/out.jsonl > OUTPUT

  PARSERS                               files                          OUTPUT
  plist/spotlight,plist/spotlight_volume  com.apple.spotlight.plist,   plaso-spotlight-prefs.tsv
                                          VolumeConfiguration.plist
  sqlite/imessage                       imessage_chat.db               plaso-messages.tsv
  mac_keychain                          login.keychain                 plaso-keychain.tsv
"""

import json
import sys

KEYS = {
    "spotlight_searched_terms:entry": ["application_display_name", "path", "search_term"],
    "spotlight_volume_configuration:store": ["partial_path", "volume_identifier"],
    "imessage:event:chat": [
        "attachment_location", "client_version", "imessage_id", "message_type",
        "offset", "read_receipt", "service", "text",
    ],
    "macos:keychain:application": ["account_name", "comments", "entry_name", "text_description"],
    "macos:keychain:internet": [
        "account_name", "comments", "entry_name", "protocol", "text_description",
        "type_protocol", "where",
    ],
}


def escape(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")


lines = []
for line in open(sys.argv[1], encoding="utf-8"):
    event = json.loads(line)
    kind = event["data_type"]
    values = [f"{k}={escape(event[k])}" for k in KEYS[kind] if event.get(k) is not None]
    lines.append("\t".join([kind, event["timestamp_desc"], str(event["timestamp"])] + values))
for line in sorted(lines):
    print(line)
