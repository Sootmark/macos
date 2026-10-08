"""plaso's Wi-Fi and launchd log events (psort JSON lines) as the TSVs
tests/logs.rs compares: one line per event of the parser given, sorted:
the file (its path under in/), the time (ISO 8601 to the 100 ns, as plaso
stores it, without a zone), what plaso calls that time, the parser, then
every value plaso read, as name=value sorted by name (plaso's formatted
message and its bookkeeping left out; newlines and tabs escaped).
Independent of this crate: no code shared.

Made with plaso 20260720 on Debian (Docker), on 2026-10-08: plaso dates a
Wi-Fi log's lines from the file's times and the current year (see
tests/oracle/README). The test files in a folder in/, plaso's wifi.log in
four copies whose times set the year (each copy's change time is when it
was copied, 2026; a gzip file's only time is the one in its header):

  in/old/wifi.log              touch -d "2014-01-05 12:00:00"
  in/old/wifi_turned_over.log  touch -d "2017-01-03 12:00:00"
  in/y2025/wifi.log            touch -d "2025-06-01 12:00:00"
  in/y2026/wifi.log            touch -d "2026-01-02 12:00:00"
  in/gz/wifi.log.gz            touch -d "2025-06-01 12:00:00", then gzip -9
  in/launchd/macos_launchd.log

  sudo docker run --rm -v "$PWD:/data" log2timeline/plaso:20260720 \\
    log2timeline --status_view none -q \\
    --parsers 'text/mac_wifi,text/macos_launchd_log' \\
    --storage-file /data/out.plaso /data/in
  sudo docker run --rm -v "$PWD:/data" log2timeline/plaso:20260720 \\
    psort --status_view none -q -a -o json_line -w /data/out.jsonl /data/out.plaso
  python3 -I gen_logs.py out.jsonl text/mac_wifi > plaso-wifi.tsv
  python3 -I gen_logs.py out.jsonl text/macos_launchd_log | gzip -9n > plaso-launchd.tsv.gz

(psort's -a keeps events it would drop as duplicates.)
"""

import datetime
import json
import sys

# plaso's bookkeeping, and its formatted message: not values it read.
SKIPPED = {
    "__container_type__",
    "__type__",
    "data_type",
    "date_time",
    "display_name",
    "message",
    "parser",
    "pathspec",
    "sha256_hash",
    "timestamp",
    "timestamp_desc",
}


def iso(micros):
    moment = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=micros)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond:06d}0"


def escape(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")


def line(event):
    spec = event["pathspec"]
    while "location" not in spec:
        spec = spec["parent"]
    name = spec["location"].split("/data/in/", 1)[-1]
    values = [
        f"{key}={escape(value)}"
        for key, value in sorted(event.items())
        if key not in SKIPPED and value is not None
    ]
    return "\t".join(
        [name, iso(event["timestamp"]), event["timestamp_desc"], event["parser"]] + values
    )


def main(path, parser):
    with open(path, encoding="utf-8") as events:
        lines = sorted(
            line(event)
            for event in map(json.loads, filter(str.strip, events))
            if event["parser"] == parser
        )
    sys.stdout.write("".join(f"{line}\n" for line in lines))


main(sys.argv[1], sys.argv[2])
