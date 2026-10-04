#!/bin/sh
# Recreates the synthetic databases, written by the sqlite3 shell (3.46.1):
#
# - TCC.db: a TCC database with the `access` table of macOS 14 and later
#   (`auth_value`, `auth_reason`, `auth_version` since macOS 11; `pid`,
#   `pid_version`, `boot_uuid`, `last_reminded` since macOS 14). TCC is
#   closed source: the statement is the one public write-ups show (Rainforest
#   QA, "A deep dive into macOS TCC.db", 2021; HackTricks, "macOS TCC"), not
#   copied from a Mac. Rows: every authorization value, reasons from user
#   consent to MDM policy and one unknown, a client given by path, an Apple
#   Events grant with its target (the indirect object), a process id and a
#   boot UUID, a reminder time.
# - knowledgeC.db, knowledgeC.db-wal: a KnowledgeC database with the
#   ZOBJECT, ZSOURCE and ZSTRUCTUREDMETADATA tables of macOS 10.14, taken
#   from plaso's knowledgec-10.14.db (../plaso/), and app focus and usage,
#   device lock, backlight, a Safari visit with its source (bundle, device)
#   and title, an object whose source row is missing, and an app focus
#   committed to the log and not yet checkpointed: both files copied while
#   the connection holds them.
#
# Synthetic data only: example bundle identifiers and documentation domains
# (RFC 2606).
#
#   sudo apt-get install sqlite3
#   sh tests/fixtures/synthetic/gen.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

# 2026-09-01 08:00:00 UTC: 1788249600 Unix seconds, 809942400 seconds of
# Mac absolute time (since 2001-01-01 UTC).
unix0=1788249600
mac0=809942400

sqlite3 TCC.db "
CREATE TABLE admin (key TEXT PRIMARY KEY NOT NULL, value INTEGER NOT NULL);
CREATE TABLE policies (id INTEGER NOT NULL PRIMARY KEY, bundle_id TEXT NOT NULL, uuid TEXT NOT NULL, display TEXT NOT NULL, UNIQUE (bundle_id, uuid));
CREATE TABLE active_policy (client TEXT NOT NULL, client_type INTEGER NOT NULL, policy_id INTEGER NOT NULL, PRIMARY KEY (client, client_type), FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE ON UPDATE CASCADE);
CREATE TABLE access (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, auth_value INTEGER NOT NULL, auth_reason INTEGER NOT NULL, auth_version INTEGER NOT NULL, csreq BLOB, policy_id INTEGER, indirect_object_identifier_type INTEGER, indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED', indirect_object_code_identity BLOB, flags INTEGER, last_modified INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)), pid INTEGER, pid_version INTEGER, boot_uuid TEXT NOT NULL DEFAULT 'UNUSED', last_reminded INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (service, client, client_type, indirect_object_identifier), FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE ON UPDATE CASCADE);
CREATE TABLE access_overrides (service TEXT NOT NULL PRIMARY KEY);
CREATE TABLE expired (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, csreq BLOB, last_modified INTEGER NOT NULL, expired_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)), PRIMARY KEY (service, client, client_type));
INSERT INTO admin VALUES ('version', 29);
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version, csreq, indirect_object_identifier_type, indirect_object_identifier, flags, last_modified, pid, pid_version, boot_uuid, last_reminded) VALUES
 ('kTCCServiceCamera', 'com.example.meet', 0, 2, 2, 1, X'FADE0C00000000300000000100000006', NULL, 'UNUSED', 0, $unix0, NULL, NULL, 'UNUSED', 0),
 ('kTCCServiceScreenCapture', 'com.example.recorder', 0, 0, 3, 1, NULL, NULL, 'UNUSED', 0, $unix0 + 60, NULL, NULL, 'UNUSED', 0),
 ('kTCCServiceSystemPolicyAllFiles', '/usr/local/bin/backup-agent', 1, 2, 3, 1, NULL, NULL, 'UNUSED', 0, $unix0 + 120, 4242, 7, '5B1E3C2A-9D4F-4E61-8A7B-0C9D8E7F6A5B', $unix0 + 86400),
 ('kTCCServiceAccessibility', 'com.example.helper', 0, 2, 6, 1, NULL, NULL, 'UNUSED', 0, $unix0 + 180, NULL, NULL, 'UNUSED', 0),
 ('kTCCServiceAppleEvents', 'com.example.automation', 0, 2, 2, 1, NULL, 0, 'com.apple.finder', 0, $unix0 + 240, NULL, NULL, 'UNUSED', 0),
 ('kTCCServicePhotos', 'com.example.gallery', 0, 3, 2, 1, NULL, NULL, 'UNUSED', 0, $unix0 + 300, NULL, NULL, 'UNUSED', 0),
 ('kTCCServiceMicrophone', 'com.example.meet', 0, 1, 99, 1, NULL, NULL, 'UNUSED', 0, $unix0 + 360, NULL, NULL, 'UNUSED', 0);"

# The tables of macOS 10.14, from plaso's file.
gunzip -c "$here/../plaso/knowledgec-10.14.db.gz" > plaso.db
schema=$(sqlite3 plaso.db ".schema ZOBJECT" ".schema ZSOURCE" ".schema ZSTRUCTUREDMETADATA")

# Objects: ZSTARTDATE and ZENDDATE whole seconds, ZCREATIONDATE with a
# fraction, as macOS writes them; ZSECONDSFROMGMT 7200 (UTC+2).
rows="
INSERT INTO ZSOURCE (Z_PK, Z_ENT, Z_OPT, ZBUNDLEID, ZDEVICEID, ZGROUPID, ZITEMID, ZSOURCEID) VALUES
 (1, 15, 1, 'com.apple.Safari', '7F3E2D1C-0B9A-4877-8665-544332211000', 'com.apple.Safari.PageContentDonation', 'A1B2C3', 'spotlight');
INSERT INTO ZSTRUCTUREDMETADATA (Z_PK, Z_ENT, Z_OPT, Z_DKSAFARIHISTORYMETADATAKEY__TITLE) VALUES
 (1, 13, 1, 'Example Domain');
INSERT INTO ZOBJECT (Z_PK, Z_ENT, Z_OPT, ZSTREAMNAME, ZVALUESTRING, ZVALUEINTEGER, ZVALUEDOUBLE, ZSTARTDATE, ZENDDATE, ZCREATIONDATE, ZSECONDSFROMGMT, ZSOURCE, ZSTRUCTUREDMETADATA, ZUUID) VALUES
 (1, 11, 1, '/device/isLocked', NULL, 0, 0.0, $mac0, $mac0 + 5, $mac0 + 5.25, 7200, NULL, NULL, '00000000-0000-4000-8000-000000000001'),
 (2, 11, 1, '/display/isBacklit', NULL, 1, 1.0, $mac0, $mac0 + 600, $mac0 + 600.5, 7200, NULL, NULL, '00000000-0000-4000-8000-000000000002'),
 (3, 11, 1, '/app/inFocus', 'com.apple.Terminal', 8999410902659233531, 8.99941090265923e18, $mac0 + 5, $mac0 + 65, $mac0 + 65.125, 7200, NULL, NULL, '00000000-0000-4000-8000-000000000003'),
 (4, 11, 1, '/safari/history', 'https://example.com/', 1903245748545110053, 1.90324574854511e18, $mac0 + 70, $mac0 + 70, $mac0 + 72.5, 7200, 1, 1, '00000000-0000-4000-8000-000000000004'),
 (5, 11, 1, '/app/usage', 'com.apple.Terminal', 8999410902659233531, 8.99941090265923e18, $mac0 + 5, $mac0 + 300, $mac0 + 300.75, 7200, NULL, NULL, '00000000-0000-4000-8000-000000000005'),
 (6, 11, 1, '/app/activity', 'com.apple.Safari', 2939589157913874707, 2.93958915791387e18, $mac0 + 70, $mac0 + 70, $mac0 + 72.5, 7200, 9, NULL, '00000000-0000-4000-8000-000000000006'),
 (7, 11, 1, '/device/isLocked', NULL, 1, 1.0, $mac0 + 600, $mac0 + 900, $mac0 + 900.5, 7200, NULL, NULL, '00000000-0000-4000-8000-000000000007');"

sqlite3 src.db "PRAGMA journal_mode=WAL; $schema $rows" >/dev/null
sqlite3 src.db <<SQL
PRAGMA wal_autocheckpoint=0;
PRAGMA wal_checkpoint(TRUNCATE);
INSERT INTO ZOBJECT (Z_PK, Z_ENT, Z_OPT, ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE, ZENDDATE, ZCREATIONDATE, ZSECONDSFROMGMT, ZUUID) VALUES
 (8, 11, 1, '/app/inFocus', 'com.example.editor', $mac0 + 900, $mac0 + 960, $mac0 + 960.5, 7200, '00000000-0000-4000-8000-000000000008');
.shell cp src.db knowledgeC.db && cp src.db-wal knowledgeC.db-wal
SQL

cp TCC.db knowledgeC.db knowledgeC.db-wal "$here/"
