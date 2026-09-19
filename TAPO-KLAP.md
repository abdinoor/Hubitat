# Tapo KLAP LAN driver

Version 1.1.0 retains the existing driver name and preference keys. No bridge is
required. This is separate from the TPAP driver; do not change Island's TPAP
assignment to use it.

## Changes

- Asynchronous callbacks drive handshake1, handshake2, requests and command
  read-back. There are no blocking sleeps or callback-result polling loops.
- One transaction at a time, a bounded 16-command queue, coalesced refreshes,
  stale-callback rejection, and a 15-second watchdog protect session sequencing.
- Keys, IV base, signature material and handshake seed are Base64 strings in
  persistent state. Legacy raw-byte sessions are discarded on the next request.
- Saving preferences validates and saves the address before refreshing, and
  invalidates the prior session and pending callbacks.
- Password hashing preserves the exact UTF-8 password, including surrounding
  whitespace. Existing username trimming is unchanged.
- Corrected the initial sequence derivation to use the last four bytes of the
  SHA-256 IV hash, matching python-kasa and independent vectors.
- Switch/level events come from device read-back, not optimistic command state.
  Level zero sends Off; optional transition duration remains unsupported.
- Session material and HTTP exception bodies are not logged. Session seeds use
  SecureRandom. Base64 storage is not encryption: protect Hubitat administration
  and backups.

## Failure handling and upgrade

Save the new source in the existing **Tapo KLAP LAN Device** driver entry.
On each assigned device, use **Initialize** or **Reset Session** once after the
upgrade. Both apply the existing preferences and start a read, not a device reboot
or factory reset. Do not change working credentials.

Failed/ambiguous requests discard queued work and the session, without replaying
commands. Ordinary failures impose a five-minute cooldown. A refused handshake
or challenge mismatch blocks authentication until Save Preferences, Initialize,
or Reset Session; investigate settings/protocol compatibility before resetting.
Polling is bounded to 30–3600 seconds. Sessions are renewed after ten minutes or
before signed sequence exhaustion. Successful reads set commsError=false and
lastError=none.

## Offline regression tests

Run from the repository root:

    groovy tapo-klap-tests.groovy

The harness requires the existing venv with cryptography and tests the actual
driver with fake credentials and mocked Hubitat callbacks. Independent Python
vectors cover both KLAP versions, password hashing, key derivation, sequence
numbers and AES frames. Lifecycle tests serialize state between callbacks and
cover IP updates, read-back, queues, stale callbacks, authentication blocking,
timeouts and session migration. The suite sends no network requests.

## Hubitat verification — 2026-09-19

Saved and compiled in existing driver entry 893, used by ten KLAP devices.
Kitchen Sink Light (device 76, 192.168.5.217) completed a fresh handshake and
encrypted status read, then reused the persisted session for a second refresh.
The sequence incremented by one across executions; all three stored key fields
were strings. Final state: commsError=false, lastError=none, on, level 62, no
active or queued work. No power or brightness commands were sent. Other KLAP
devices were not individually tested; Island's TPAP driver was unchanged.

Protocol reference: the local python-kasa implementation, corresponding to
https://github.com/python-kasa/python-kasa/blob/master/kasa/transports/klaptransport.py.
