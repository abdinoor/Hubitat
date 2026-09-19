# Tapo TPAP LAN driver (experimental)

The standalone **Tapo TPAP LAN Device** driver implements the TPAP mode observed
on the Kitchen Island Lights S505D(US), at 192.168.6.116. It does not replace or
modify the existing KLAP driver and needs no Python service or LAN bridge at runtime.

## Status and scope

Implemented: on, off, brightness (0 means off; 1–100 turns on), refresh, polling,
SPAKE2+ P-256/SHA-256, AES-128-CCM, device confirmation, and DAC certificate/proof
verification against the pinned TP-Link root. Commands are followed by a status
read; switch/level events reflect that read, not optimistic command state.

Supported negotiation is deliberately narrow:

- HTTP TPAP with tls=0, PAKE userpw (advertised value 2), cipher suite 1,
  encryption aes_128_ccm.
- password_shadow/passwd_id=2 and 4 use lowercase SHA-1 of the exact UTF-8
  account password. Verified on Sink (mode 2) and Island (mode 4), both S505D.
  For mode 4 this supplies the local-control secret rather than the raw account
  password; support on other models is not established. No-transform
  username/password mode is also implemented.
- 1–10,000 PBKDF2 iterations (target returned 3,000).
- No TLS downgrade, camera/robot authentication, other password transforms,
  other curves/ciphers, energy monitoring, or timed brightness transitions.
  The optional setLevel duration argument is ignored.

Unsupported modes fail explicitly. This driver does not fall back to KLAP.

### Verification on 2026-09-18

The real device accepted TPAP registration and selected the mode above, including
while HTTP discovery returned tpap_preferred=false with no TPAP parameters and
UDP discovery advertised KLAP v2. The initial implementation incorrectly treated
that preference as proof that TPAP was unavailable. The driver now attempts the
supported TPAP registration in this specific compatibility-mode response, with
DAC proof required. It does not downgrade a device that explicitly advertises TLS.

The original mode-4 raw-password implementation reached pake_share but returned
-2203. The account password was correct: Island requires its SHA-1-derived
local-control secret. Static inspection of the Tapo app's local-control setup
path identified that derivation; a single read-only hardware test confirmed it.
The driver now derives the secret internally from the saved account password.

**A complete read-only TPAP hardware session is now verified on Kitchen Sink
Light (192.168.5.217)** after adding password-shadow mode 2. The exact Groovy
driver completed PAKE, verified the device's DAC certificate/proof, and decrypted
get_device_info. The Sink's Hubitat entity remains on its working KLAP driver;
this was a local harness test, not a driver reassignment. No light commands were sent.

**Island (192.168.6.116) also completed the authenticated local harness read**,
including DAC verification and encrypted get_device_info, reporting S505D,
switch off, brightness 62. No power or brightness commands were sent.

Both S505D switches report firmware 1.4.0 Build 260611. Their Hubitat credential
fields were visually compared and match. After the user factory-reset Island,
it advertises TPAP rather than KLAP and returns password-shadow mode 4.
Both discovery owner hashes match the same account. Factory resetting alone
did not resolve the driver's incorrect secret derivation.

The driver
compiles and saves successfully in Hubitat's Drivers Code editor. Sandbox fixes
replace System.arraycopy with indexed copies and avoid array-typed closure
parameters and array class expressions.
All 26 offline tests pass under Groovy 2.4.21/Java 8 and Groovy 4/Java 23.
Island also completed authentication and a status read **inside Hubitat** with
commsError=false, off, and level 62. Its entity had been reassigned to KLAP;
the TPAP driver assignment and supplied connection preferences were restored.
An idempotent Off command (already off) completed with authenticated read-back,
without changing the lighting. On and brightness changes have not been physically
tested. Successful communication sets lastError to "none", since Hubitat did not
persist an empty-string error clear across page reloads.

## Installation

1. In Hubitat, add a **new** Drivers Code entry containing
   tapo-tpap-lan-driver.groovy and save it. Keep the KLAP driver.
2. Use a dedicated virtual device with type **Tapo TPAP LAN Device** for initial
   testing. Do not overwrite a working Matter or KLAP entity.
3. Set Device IPv4 address, TP-Link email, and TP-Link password, then Save
   Preferences. The new preference names are deviceIp, tpapUsername and
   tpapPassword; existing KLAP preferences are not migrated.
4. Use Refresh first. A successful authenticated response publishes switch/level
   and sets commsError=false. Check lastError if it fails.
5. Test physical on/off/brightness only once Refresh succeeds.

The switch must accept TPAP registration, but may advertise KLAP as preferred.
There is no need to change a global Tapo compatibility setting just to test this
driver; doing so can affect other devices.

Saving preferences/Initialize/Reset Session clears pending commands and session
keys and schedules a read. Poll interval defaults to 300 seconds, bounded to
30–3,600 seconds. Reset Session does not reboot or reset the physical device.

## Safety and implementation notes

- singleThreaded=true serializes Hubitat entry points. A bounded queue permits
  only one HTTP request at a time. Callbacks include transaction and phase IDs,
  and late callbacks are ignored.
- There is no busy-wait loop around asynchronous HTTP calls. Each request has an
  8-second HTTP timeout and a 20-second watchdog.
- Failed/ambiguous commands are **not replayed**. Failure drops pending work and
  starts a five-minute cooldown. Authentication/access/lockout errors (-1501,
  -2101, -2203) instead block further login attempts until authentication
  compatibility/settings are resolved and Save Preferences/Reset
  Session/Initialize is used. Do not repeatedly reset the session after rejected
  proofs: device-side lockout can result even with valid account credentials.
- Session keys/nonces are base64 strings so they survive Hubitat state JSON
  serialization. A nonce is reserved before transmission. Sessions are discarded
  after ten minutes or sequence exhaustion; nonce counters never wrap.
- AES-CCM tags, exact PAKE confirmation bytes, and response sequence are checked
  before accepting data. A device advertising DAC must return a valid proof;
  missing proofs do not silently bypass verification.
- Passwords are not trimmed or case-normalized, embedded in source, or logged.
  Debug logging reports only stage names. HTTP exception bodies/URLs are not
  logged because they can contain session tokens.
- Hubitat stores configured credentials and session material. Base64 is **not
  encryption**. Protect hub administration and backups; do not publish device
  state dumps.
- The portable elliptic-curve arithmetic uses BigInteger and is **not
  constant-time**. This experimental implementation is not cryptographically
  audited. Only use on a trusted LAN, initially with non-critical lighting.

## Local testing

Run from the repository root. Groovy is required. Python dependencies are
test-only and are not required on Hubitat:

    venv/bin/python -m pip install cryptography ecdsa
    groovy tapo-tpap-tests.groovy

The offline suite compiles the actual driver and exercises it with Hubitat
stubs. Independent Python cryptography/ecdsa code generates fake-credential
server-side PAKE vectors, CCM vectors, and a test certificate chain. It also
checks the RFC 5869 HKDF vector, invalid points, packet tampering, replay
rejection, lifecycle/queue handling, JSON state persistence and fail-closed
negotiation. Tests do not access your devices.

Optional **read-only** hardware test:

    venv/bin/python tapo-tpap-live.py --host 192.168.6.116 --username YOUR_TAPO_EMAIL

This prompts without echo, passes the password through a subprocess pipe (not
arguments or environment), and runs the exact Groovy driver's request/callback
flow. It never saves the password or sends set_device_info. It first runs the
offline suite. Run this Python wrapper, not the Groovy --live implementation
directly.

## References and license

The TPAP wire layout, SPAKE2+ transcript conventions, fixed points, KDF labels
and root certificate are based on the unmerged python-kasa TPAP work:
https://github.com/python-kasa/python-kasa/pull/1592
at commit e7084472972f08f2e2235b342f3964aedbfaeb3b. This driver is an independent
Groovy implementation with a narrower supported scope; it is not an official
TP-Link or Hubitat driver.

The new TPAP driver and harness are GPL-3.0-or-later. See
licenses/TPAP-GPL-3.0.txt for the upstream notice and license. Existing repository
files retain their own licenses.

Hubitat single-threaded execution:
https://docs2.hubitat.com/release-notes/release-229

TP-Link compatibility setting:
https://www.tp-link.com/us/support/faq/4416/
