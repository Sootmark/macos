#!/bin/sh
# Recreates the oracle files: every row of the test databases as the sqlite3
# shell (3.46.1) reads them, one tab-separated line per entry, NULL as \N,
# times as stored (seconds, six decimals), blobs in hex. tests/oracle.rs
# reads the same databases with this crate and compares field by field.
#
#   sudo apt-get install sqlite3
#   sh tests/oracle/gen.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
fixtures="$here/../fixtures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A time column as stored, NULL kept.
t() { echo "iif($1 IS NULL, NULL, printf('%.6f', $1))"; }

dump() { sqlite3 -batch -noheader -separator '	' -nullvalue '\N' "$1" "$2"; }

quarantine="SELECT rowid, LSQuarantineEventIdentifier, $(t LSQuarantineTimeStamp),
 LSQuarantineAgentBundleIdentifier, LSQuarantineAgentName, LSQuarantineDataURLString,
 LSQuarantineSenderName, LSQuarantineSenderAddress, LSQuarantineTypeNumber,
 LSQuarantineOriginTitle, LSQuarantineOriginURLString, hex(LSQuarantineOriginAlias)
 FROM LSQuarantineEvent ORDER BY rowid"

# Before macOS 11: `allowed`, no reason.
tcc_old="SELECT rowid, service, client, client_type, allowed, NULL, last_modified,
 indirect_object_identifier, hex(csreq) FROM access ORDER BY rowid"
tcc="SELECT rowid, service, client, client_type, auth_value, auth_reason, last_modified,
 indirect_object_identifier, hex(csreq) FROM access ORDER BY rowid"

knowledgec="SELECT o.Z_PK, o.ZSTREAMNAME, o.ZVALUESTRING, o.ZVALUEINTEGER,
 $(t o.ZSTARTDATE), $(t o.ZENDDATE), $(t o.ZCREATIONDATE), o.ZSECONDSFROMGMT, o.ZUUID,
 s.ZBUNDLEID, s.ZDEVICEID,
 coalesce(m.Z_DKSAFARIHISTORYMETADATAKEY__TITLE, m.Z_DKAPPLICATIONACTIVITYMETADATAKEY__TITLE)
 FROM ZOBJECT o LEFT JOIN ZSOURCE s ON o.ZSOURCE = s.Z_PK
 LEFT JOIN ZSTRUCTUREDMETADATA m ON o.ZSTRUCTUREDMETADATA = m.Z_PK
 ORDER BY o.Z_PK"

cp "$fixtures/plaso/quarantine.db" "$fixtures/plaso/TCC-test.db" "$work/"
gunzip -c "$fixtures/plaso/knowledgec-10.13.db.gz" > "$work/knowledgec-10.13.db"
gunzip -c "$fixtures/plaso/knowledgec-10.14.db.gz" > "$work/knowledgec-10.14.db"
cp "$fixtures/synthetic/TCC.db" "$fixtures/synthetic/knowledgeC.db" \
  "$fixtures/synthetic/knowledgeC.db-wal" "$work/"

dump "$work/quarantine.db" "$quarantine" > "$here/quarantine.db.tsv"
dump "$work/TCC-test.db" "$tcc_old" > "$here/TCC-test.db.tsv"
dump "$work/TCC.db" "$tcc" > "$here/TCC.db.tsv"
dump "$work/knowledgec-10.13.db" "$knowledgec" > "$here/knowledgec-10.13.db.tsv"
dump "$work/knowledgec-10.14.db" "$knowledgec" > "$here/knowledgec-10.14.db.tsv"
# With its log: the shell applies it.
dump "$work/knowledgeC.db" "$knowledgec" > "$here/knowledgeC.db.tsv"
