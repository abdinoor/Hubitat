# Tuya LAN Device 1.1.1

Standalone Hubitat driver for the existing Tuya 3.3 AES-ECB/CRC32 devices.
Existing preference names, device identities, and DP mapping are preserved:
DP 1 is the relay and DP 2 is brightness on a 0–1000 scale. This is not support
for Tuya 3.4/3.5 or arbitrary product datapoint mappings.

## Improvements

- Installation and preference updates share a self-contained Initialize path.
- Local keys use a password preference and are never published in new events or
  logs. Initialization removes the redundant localKey data value only when a
  configured preference is available; legacy data-only setups remain readable.
- A bounded, JSON-safe receive buffer assembles fragmented TCP frames, including
  partial prefixes and headers. Partial ciphertext is never decrypted. Stale
  fragments expire after 15 seconds; frames are limited to 64 KiB.
- Incoming prefix, declared length, suffix and CRC32 are checked before
  decryption. CRC detects corruption, not malicious tampering/authentication.
- Sequence numbers are persisted and incremented before transmission.
- Commands run one at a time with a bounded queue and a 12-second watchdog.
  An acknowledgement triggers a status query; switch/level events come only
  from validated device reports. Failures discard pending work without replay.
- Binary TCP uses Hubitat's rawSocket interface, not the HubAction request/response
  path. A connection is opened for each transaction, reused for command read-back,
  and closed on completion, failure, Initialize or uninstall. Uncorrelated socket
  status callbacks cannot abort a newer request; the watchdog bounds failures.
- Successful status reads report commsError=false and lastError=none. Errors
  contain sanitized reasons, not raw exception bodies, packets or secrets.

Use Initialize once after upgrading to apply existing settings and perform a
read-only refresh. It does not reboot the physical device. Poll intervals are
bounded to 30–3600 seconds. Level zero sends Off; transition/ramp/onTime remain
unsupported. Existing automation references and device IDs do not change.

## Secret handling limitations

This update does not delete historical logs, events, backups, or old test fixtures
that may contain keys recorded previously. Removing an attribute declaration is
not historical-data erasure. Protect Hubitat administration/backups and do not
share old logs. If a key was disclosed outside trusted systems, rotate it through
the device's supported setup process and update the preference. No key rotation
is performed by this driver. Password masking is not encryption at rest.

## Offline tests

    groovy tuya-driver-tests.groovy

The harness loads the actual production source, stubs Hubitat APIs, and sends no
network traffic. It uses fake credentials and independent Python cryptography
and zlib vectors from tests/tuya_vectors.py (requires the existing venv).
Coverage includes every frame split boundary, state serialization, checksum and
length failures, sequence progression, lifecycle, command acknowledgement and
read-back, queue limits, stale timeouts, transport failures and secret logging.

The older tuya-lan-tests.groovy and tuya-lan-hubitat-tests.groovy files contain
copied implementations and historical fixtures. They are not the regression
suite for this updated production driver.

## Initial 1.1.0 deployment verification (2026-09-19)

Hubitat accepted and saved version 1.1.0 in the existing Tuya LAN Device driver
(driver 699); device assignments were preserved. All 20 offline regression
tests passed under Groovy 4 and Groovy 2.4.21.

Read-only Initialize/status checks on Kitchen Hall Lights (133) and Dining Room
Light (84) timed out. Kitchen Hall's TCP port 6668 was reachable, but that alone
does not establish a successful Tuya exchange. The driver reported commsError
without publishing an optimistic switch/level change. No power or brightness
commands were sent. Live status/control success remains unverified; the cause
of these timeouts has not been established.

## 1.1.1 transport regression correction

The user confirmed Kitchen Hall control worked before 1.1.0 and still worked in
the Tuya app. The exact encrypted read requests generated inside Hubitat were
sent directly from the development computer: the standard command 10 received
a response in about 0.17 seconds and the alternate command 13 in about 0.22
seconds. Hubitat's HubAction path timed out on these requests. Switching the
same standard query to binary rawSocket inside Hubitat produced a successfully
decrypted status report (on, level 52), commsError=false and lastError=none.
No key change, device reset, alternate-query fallback or lighting command was
needed. The exact internal reason HubAction timed out is not established.

Temporary diagnostic commands and packet capture were removed from the final
driver; Initialize clears their temporary state fields. The suite now has 24
passing tests on both Groovy 4 and Groovy 2.4.21, including socket lifecycle,
connect/send failures and late socket-status callbacks.

The clean 1.1.1 source was saved in shared Hubitat driver 699 and verified after
reloading the editor. Kitchen Hall completed Initialize and a subsequent Refresh
with on/52; Dining Room (84) completed Initialize with off/100. Both reported
commsError=false, lastError=none, empty queues, no pending request and a closed
socket after completion. Kitchen Hall's temporary diagnostic state was absent.
Only read-only device requests were sent during these checks; physical command
execution was not exercised. Other devices sharing driver 699 were not individually
tested.
