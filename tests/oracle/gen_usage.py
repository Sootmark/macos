"""plaso's application usage, document versions, Notes and Notification
Center events (psort JSON lines) as the TSV tests/usage.rs compares: one
line per event, sorted: its kind, which time, the time in microseconds,
and its values as key=value (newlines and tabs escaped).
Run: python3 -I gen_usage.py plaso.jsonl > plaso-usage.tsv
"""

import json
import sys

KEYS = {
    "application_usage": ["activity", "application", "application_version", "bundle_identifier", "count"],
    "document_versions": ["name", "path", "user_sid", "version_path"],
    "notes": ["text", "title"],
    "notification_center": ["bundle_name", "message_body", "presented", "subtitle", "title"],
}


def escape(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")


lines = []
for line in open(sys.argv[1], encoding="utf-8"):
    event = json.loads(line)
    kind = event["data_type"].split(":")[1]
    values = [f"{k}={escape(event[k])}" for k in KEYS[kind] if event.get(k) is not None]
    lines.append("\t".join([kind, event["timestamp_desc"], str(event["timestamp"])] + values))
for line in sorted(lines):
    print(line)
