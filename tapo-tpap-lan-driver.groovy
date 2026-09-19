/*
 * Tapo TPAP LAN switch/dimmer — experimental, HTTP TPAP suite 1.
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Protocol reference: python-kasa contributors / ZeliardM, PR #1592,
 * e7084472972f08f2e2235b342f3964aedbfaeb3b (GPL-3.0-or-later).
 * https://github.com/python-kasa/python-kasa/pull/1592
 * Read TAPO-TPAP.md before installing. No external library or bridge.
 */
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import groovy.transform.Field
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

metadata {
    definition(name: "Tapo TPAP LAN Device", namespace: "tapo", author: "Dan Abdinoor", singleThreaded: true) {
        capability "Switch"
        capability "SwitchLevel"
        capability "Refresh"
        capability "Initialize"
        attribute "connection", "string"
        attribute "commsError", "string"
        attribute "lastError", "string"
        attribute "deviceIP", "string"
        command "resetSession"
    }
    preferences {
        input name: "deviceIp", type: "text", title: "Device IPv4 address", required: true
        input name: "tpapUsername", type: "text", title: "TP-Link account email (case-sensitive)", required: true
        input name: "tpapPassword", type: "password", title: "TP-Link account password", required: true
        input name: "pollSeconds", type: "number", title: "Poll interval (seconds)", defaultValue: 300, range: "30..3600"
        input name: "logEnable", type: "bool", title: "Log stage names only (no credentials or payloads)", defaultValue: false
    }
}

@Field static final BigInteger P = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
@Field static final BigInteger ORDER = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
@Field static final BigInteger CURVE_B = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
@Field static final String GENERATOR = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
@Field static final String POINT_M = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
@Field static final String POINT_N = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
@Field static final String ROOT_CA = """-----BEGIN CERTIFICATE-----
MIICNzCCAdygAwIBAgIUNLD7w5j5WU/efCe8bqkfGSRGgLYwCgYIKoZIzj0EAwIw
ezEnMCUGA1UEAwweVFAtTElOSyBTWVNURU1TIERFVklDRSBST09UIENBMR0wGwYD
VQQKDBRUUC1MSU5LIFNZU1RFTVMgSU5DLjEPMA0GA1UEBwwGSXJ2aW5lMRMwEQYD
VQQIDApDYWxpZm9ybmlhMQswCQYDVQQGEwJVUzAgFw0yNDExMjIwMjU3NDhaGA8y
MDU0MTExNTAyNTc0OFowezEnMCUGA1UEAwweVFAtTElOSyBTWVNURU1TIERFVklD
RSBST09UIENBMR0wGwYDVQQKDBRUUC1MSU5LIFNZU1RFTVMgSU5DLjEPMA0GA1UE
BwwGSXJ2aW5lMRMwEQYDVQQIDApDYWxpZm9ybmlhMQswCQYDVQQGEwJVUzBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABLwo8H9H6BoJDvcoewi4wPrPryVXir4z4yXV
n29R5XCAcFfKk06pYPupG6pjaKOLKWXnaOdPZThDFxwGLo3urV2jPDA6MAsGA1Ud
DwQEAwIBhjAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBRivfUtiHYsZBOKo80uZEwk
XhBkdDAKBggqhkjOPQQDAgNJADBGAiEA+7j5jemtXcGYN0unH+9rjVhVAL7WrsOi
5rbc0IIvD6MCIQCZuGGssu4Ygt2V8Vr0QF2fO9wxfNB3aRRMYQ+6lMrLGA==
-----END CERTIFICATE-----"""

def installed() { initialize() }
def updated() { initialize() }
def initialize() {
    unschedule()
    state.queue = []
    state.active = null
    state.session = null
    state.handshake = null
    state.retryAfter = 0
    state.authBlocked = false
    state.serial = ((state.serial ?: 0) as Long) + 1L
    sendEvent(name: "connection", value: "TPAP LAN")
    try {
        String host = configuredHost()
        updateDataValue("deviceIP", host)
        sendEvent(name: "deviceIP", value: host)
        runIn(1, "poll")
    } catch (Exception e) { failSafe(e) }
}
def resetSession() { initialize() }
def refresh() { enqueue("get_device_info", [:]) }
def on() { enqueue("set_device_info", [device_on: true]) }
def off() { enqueue("set_device_info", [device_on: false]) }
def setLevel(level, duration = null) {
    int value = Math.max(0, Math.min(100, (level as BigDecimal).intValue()))
    // Transition duration is not implemented.
    if (value == 0) off()
    else enqueue("set_device_info", [device_on: true, brightness: value])
}
def poll() {
    refresh()
    runIn(Math.max(30, Math.min(3600, (settings.pollSeconds ?: 300) as Integer)), "poll")
}
String configuredHost() {
    String host = settings.deviceIp?.trim()
    List parts = host?.tokenize(".") ?: []
    check(host != null && host ==~ /(?:\d{1,3}\.){3}\d{1,3}/ && parts.every { it.toInteger() <= 255 }, "Set a valid device IPv4 address")
    check(settings.tpapUsername && settings.tpapPassword, "Set the TP-Link username and password")
    return host
}
void enqueue(String method, Map params) {
    if (state.authBlocked) {
        if (method != "get_device_info") log.warn "TPAP authentication is blocked; resolve authentication compatibility/settings before Reset Session"
        return
    }
    if (now() < ((state.retryAfter ?: 0) as Long)) {
        if (method != "get_device_info") log.warn "TPAP command rejected during connection-error cooldown"
        return
    }
    List queue = state.queue ?: []
    if (method == "get_device_info" && (queue.any { it.method == method } || state.active?.command?.method == method)) return
    if (queue.size() >= 16) { log.warn "TPAP command queue full; command rejected"; return }
    queue << [method: method, params: params]
    state.queue = queue
    drainQueue()
}
def drainQueue() {
    if (state.active || !(state.queue)) return
    try {
        String host = configuredHost()
        List queue = state.queue
        Map command = queue.remove(0)
        state.queue = queue
        long serial = ((state.serial ?: 0) as Long) + 1L
        state.serial = serial
        state.active = [id: serial, host: host, command: command]
        Map session = state.session
        if (session && session.host == host && (session.expires as Long) > now() && (session.seq as Long) <= 0xffffffffL) {
            sendSecure(command)
        } else {
            state.session = null
            state.handshake = null
            loginStep("discover", [sub_method: "discover"])
        }
    } catch (Exception e) { failSafe(e) }
}
void loginStep(String stage, Map params) {
    String uri = "http://" + state.active.host + ":" + (state.handshake?.port ?: 80) + "/"
    issue(stage, uri, JsonOutput.toJson([method: "login", params: params]), false)
}
void issue(String stage, String uri, Object body, boolean binary) {
    Map active = state.active
    active.stage = stage
    state.active = active
    Map token = [id: active.id, stage: stage]
    runIn(20, "requestTimedOut", [data: token])
    if (settings.logEnable) log.debug "TPAP stage: " + stage
    asynchttpPost("tpapResponse", [uri: uri, timeout: 8,
        contentType: binary ? "application/octet-stream" : "application/json",
        requestContentType: binary ? "application/octet-stream" : "application/json", body: body], token)
}
boolean currentRequest(Map token) {
    return state.active && token && state.active.id == token.id && state.active.stage == token.stage
}
def requestTimedOut(Map token) {
    if (currentRequest(token)) fail("Request timed out; pending commands discarded")
}
def tpapResponse(response, Map token) {
    if (!currentRequest(token)) return
    unschedule("requestTimedOut")
    try {
        check(!response.hasError() && response.getStatus() == 200, "HTTP request failed (status " + response.getStatus() + ")")
        if (token.stage == "secure" || token.stage == "verify") {
            byte[] plaintext = decryptFrame(state.session, binaryBody(response.getData()), state.active.seq as Long)
            Map reply = new JsonSlurper().parseText(new String(plaintext, "UTF-8")) as Map
            checkReply(reply, "Device command")
            if (token.stage == "secure" && state.active.command.method == "set_device_info") {
                sendSecure([method: "get_device_info", params: [:]], "verify")
            } else {
                check(reply.result instanceof Map, "Device info missing")
                publishInfo(reply.result)
                if (state.active.command.method == "set_device_info") {
                    Map wanted = state.active.command.params
                    check(wanted.every { k, v -> reply.result[k] == v }, "Command acknowledged but read-back did not match")
                }
                sendEvent(name: "commsError", value: "false")
                // Hubitat does not persist an empty string as a cleared state.
                sendEvent(name: "lastError", value: "none")
                state.active = null
                runInMillis(50, "drainQueue")
            }
            return
        }
        Map reply = response.getJson() as Map
        checkReply(reply, token.stage)
        check(reply.result instanceof Map, "Missing handshake result")
        Map result = reply.result
        if (token.stage == "discover") {
            Map tpap
            if (result.tpap instanceof Map) {
                tpap = result.tpap
            } else {
                // S505D compatibility mode hides TPAP metadata, but still accepts
                // pake_register. Preference is not a protocol capability switch.
                check(!result.containsKey("tpap") && result.sub_method == "discover" && result.tpap_preferred == false,
                      "Device returned no usable TPAP discovery information")
                // Probe only our supported suite; never disable DAC on this path.
                tpap = [tls: 0, port: 80, pake: [2], dac: 1]
            }
            check(tpap.tls == 0, "Only HTTP TPAP (tls=0) supported; TLS is not downgraded")
            check(tpap.pake instanceof List && tpap.pake.contains(2), "Device does not support user-password PAKE")
            int port = (tpap.port ?: 80) as Integer
            check(port > 0 && port <= 65535, "Invalid TPAP port")
            byte[] random = randomBytes(32)
            state.handshake = [port: port, mac: result.mac, dac: tpap.dac == 1, random: b64(random)]
            String user = tpap.user_hash_type == 1 ? hex(hash("SHA-256", utf8("admin"))).toUpperCase() : hex(hash("MD5", utf8("admin")))
            loginStep("register", [sub_method: "pake_register", username: user, user_random: b64(random),
                cipher_suites: [1], encryption: ["aes_128_ccm"], passcode_type: "userpw", stok: null])
        } else if (token.stage == "register") {
            Map handshake = state.handshake
            Map share = makeShare(result, unb64(handshake.random), credentialString(result), randomScalar())
            handshake.shared = share.shared
            handshake.confirm = share.confirm
            Map params = share.params
            if (handshake.dac) {
                handshake.dacNonce = b64(randomBytes(32))
                params.dac_nonce = handshake.dacNonce
            }
            state.handshake = handshake
            loginStep("share", params)
        } else if (token.stage == "share") {
            Map handshake = state.handshake
            check(equalBytes(unb64(result.dev_confirm), unb64(handshake.confirm)), "Device PAKE confirmation mismatch")
            byte[] shared = unb64(handshake.shared)
            if (handshake.dac) verifyDac(result, shared, unb64(handshake.dacNonce))
            String sid = (result.sessionId ?: result.stok ?: "").toString()
            check(sid ==~ /[A-Za-z0-9_-]{1,256}/, "Invalid session identifier")
            check(result.start_seq instanceof Number, "Missing session sequence")
            long seq = result.start_seq as Long
            check(seq >= 0 && seq <= 0xffffffffL, "Invalid session sequence")
            state.session = sessionKeys(shared) + [sid: sid, seq: seq, host: state.active.host, port: handshake.port, expires: now() + 600000L]
            state.handshake = null
            sendSecure(state.active.command)
        } else check(false, "Unknown handshake stage")
    } catch (Exception e) { failSafe(e) }
}
String numericError(Object code) { code instanceof Number ? code.toString() : "(missing)" }
void checkReply(Map reply, String stage) {
    if (reply.error_code == -2203 || reply.error_code == -2101 || reply.error_code == -1501) {
        state.authBlocked = true
        check(false, "Authentication/access rejected during " + stage + " (" + numericError(reply.error_code) + "); credentials or protocol compatibility require investigation. Automatic login retries stopped")
    }
    check(reply.error_code instanceof Number && reply.error_code == 0, stage + " error " + numericError(reply.error_code))
}
void sendSecure(Map command, String stage = "secure") {
    Map session = state.session
    long seq = session.seq as Long
    check(seq >= 0 && seq <= 0xffffffffL, "Session sequence exhausted; refresh to reconnect")
    // Reserve the nonce before IO; never replay a command after failure.
    session.seq = seq + 1L
    state.session = session
    Map active = state.active
    active.seq = seq
    state.active = active
    byte[] body = utf8(JsonOutput.toJson(command + [requestTimeMils: now()]))
    byte[] frame = cat([u32(seq), ccmEncrypt(unb64(session.key), nonceFor(unb64(session.nonce), seq), body)])
    issue(stage, "http://" + session.host + ":" + session.port + "/stok=" + session.sid + "/ds", frame, true)
}
void publishInfo(Map info) {
    if (info.device_on instanceof Boolean) sendEvent(name: "switch", value: info.device_on ? "on" : "off")
    if (info.brightness instanceof Number) sendEvent(name: "level", value: info.brightness, unit: "%")
    [model: "model", fw_ver: "firmware", hw_ver: "hardware"].each { k, v ->
        if (info[k] instanceof String) updateDataValue(v, info[k])
    }
}
void failSafe(Exception e) {
    // HTTP exception messages may contain session URLs or bodies.
    String safe = e instanceof IllegalArgumentException && e.message?.startsWith("TPAP: ") ? e.message.substring(6) : e.class.simpleName + " during " + (state.active?.stage ?: "setup")
    fail(safe)
}
void fail(String reason) {
    state.session = null
    state.handshake = null
    state.active = null
    state.queue = []
    state.retryAfter = now() + 300000L
    unschedule("requestTimedOut")
    sendEvent(name: "commsError", value: "true")
    sendEvent(name: "lastError", value: reason)
    log.warn "TPAP: " + reason + (state.authBlocked ? "; waiting for explicit Reset Session after investigation" : "; no automatic command replay (5-minute cooldown)")
}

// Cryptographic helpers are pure functions, tested independently of Hubitat.
void check(boolean condition, String message) {
    if (!condition) throw new IllegalArgumentException("TPAP: " + message)
}
byte[] utf8(String text) { text.getBytes("UTF-8") }
String b64(byte[] value) { value.encodeBase64().toString() }
byte[] unb64(Object value) {
    check(value instanceof String && value.length() <= 131072 && value.length() % 4 == 0 && value ==~ /(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/, "Invalid base64 field")
    byte[] decoded = value.decodeBase64()
    check(b64(decoded) == value, "Non-canonical base64 field")
    return decoded
}
String hex(byte[] value) { value.encodeHex().toString() }
byte[] bytes(List values) {
    byte[] result = new byte[values.size()]
    for (int i = 0; i < values.size(); i++) result[i] = (byte) values[i]
    return result
}
byte[] slice(byte[] value, int start, int end) {
    check(start >= 0 && end >= start && end <= value.length, "Invalid byte slice")
    byte[] out = new byte[end - start]
    // Hubitat blocks java.lang.System, including arraycopy.
    for (int i = 0; i < out.length; i++) out[i] = value[start + i]
    return out
}
byte[] cat(List values) {
    int size = values.sum { it.length } ?: 0
    byte[] result = new byte[size]
    int offset = 0
    values.each { v ->
        for (int i = 0; i < v.length; i++) result[offset + i] = v[i]
        offset += v.length
    }
    return result
}
byte[] hash(String algorithm, byte[] value) { MessageDigest.getInstance(algorithm).digest(value) }
boolean equalBytes(byte[] a, byte[] b) { MessageDigest.isEqual(a, b) }
byte[] hmac(byte[] key, byte[] value) {
    Mac mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(key.length ? key : new byte[32], "HmacSHA256"))
    return mac.doFinal(value)
}
byte[] hkdf(byte[] input, byte[] salt, byte[] info, int length) {
    check(length > 0 && length <= 8160, "Invalid HKDF length")
    byte[] prk = hmac(salt, input)
    byte[] previous = new byte[0]
    List blocks = []
    for (int counter = 1; counter <= (length + 31).intdiv(32); counter++) {
        previous = hmac(prk, cat([previous, info, bytes([counter])]))
        blocks << previous
    }
    return slice(cat(blocks), 0, length)
}
byte[] pbkdf2(byte[] password, byte[] salt, int iterations, int length) {
    check(iterations > 0 && iterations <= 10000 && length > 0 && length <= 80, "Unsupported PBKDF2 work factor")
    Mac mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(password.length ? password : new byte[32], "HmacSHA256"))
    List blocks = []
    for (int block = 1; block <= (length + 31).intdiv(32); block++) {
        byte[] u = mac.doFinal(cat([salt, u32(block)]))
        byte[] t = slice(u, 0, u.length)
        for (int round = 1; round < iterations; round++) {
            u = mac.doFinal(u)
            for (int j = 0; j < 32; j++) t[j] = (byte)((t[j] & 255) ^ (u[j] & 255))
        }
        blocks << t
    }
    return slice(cat(blocks), 0, length)
}
byte[] randomBytes(int length) { byte[] out = new byte[length]; new SecureRandom().nextBytes(out); out }
BigInteger randomScalar() {
    BigInteger value = BigInteger.ZERO
    while (value.signum() == 0 || value >= ORDER) value = new BigInteger(1, randomBytes(32))
    return value
}
byte[] u32(long number) {
    check(number >= 0 && number <= 0xffffffffL, "Invalid unsigned sequence")
    return bytes([number >> 24, number >> 16, number >> 8, number])
}
byte[] unsignedBytes(BigInteger value, int size) {
    byte[] raw = value.toByteArray()
    if (raw.length > size && raw[0] == 0) raw = slice(raw, 1, raw.length)
    check(raw.length <= size, "Integer too large")
    byte[] out = new byte[size]
    for (int i = 0; i < raw.length; i++) out[size - raw.length + i] = raw[i]
    return out
}
// TP-Link uses variable-length w encoding, not fixed-width RFC encoding.
byte[] encodeW(BigInteger value) {
    int size = Math.max(1, (value.bitLength() + 7).intdiv(8))
    byte[] raw = unsignedBytes(value, size)
    return size % 2 == 1 && (raw[0] & 128) != 0 ? cat([bytes([0]), raw]) : raw
}
byte[] lengthPrefix(byte[] value) {
    byte[] size = new byte[8]
    long length = value.length
    for (int i = 0; i < 8; i++) size[i] = (byte)(length >> (8 * i))
    return cat([size, value])
}
List decodePoint(byte[] sec) {
    check((sec.length == 33 && (sec[0] == 2 || sec[0] == 3)) || (sec.length == 65 && sec[0] == 4), "Invalid P-256 point encoding")
    BigInteger x = new BigInteger(1, slice(sec, 1, 33))
    check(x < P, "P-256 coordinate out of range")
    BigInteger rhs = x.pow(3).subtract(x.multiply(BigInteger.valueOf(3))).add(CURVE_B).mod(P)
    BigInteger y
    if (sec.length == 65) y = new BigInteger(1, slice(sec, 33, 65))
    else {
        y = rhs.modPow(P.add(BigInteger.ONE).shiftRight(2), P)
        if ((y.testBit(0) ? 1 : 0) != (sec[0] & 1)) y = P.subtract(y)
    }
    check(y < P && y.multiply(y).mod(P) == rhs, "P-256 point is not on the curve")
    return [x, y]
}
byte[] encodePoint(List point) {
    check(point != null, "P-256 point at infinity")
    return cat([bytes([4]), unsignedBytes(point[0], 32), unsignedBytes(point[1], 32)])
}
List pointAdd(List a, List b) {
    if (a == null) return b
    if (b == null) return a
    BigInteger x1 = a[0], y1 = a[1], x2 = b[0], y2 = b[1]
    if (x1 == x2 && y1.add(y2).mod(P).signum() == 0) return null
    BigInteger slope = x1 == x2 ? x1.pow(2).multiply(BigInteger.valueOf(3)).subtract(BigInteger.valueOf(3)).multiply(y1.shiftLeft(1).modInverse(P)).mod(P) : y2.subtract(y1).multiply(x2.subtract(x1).mod(P).modInverse(P)).mod(P)
    BigInteger x = slope.pow(2).subtract(x1).subtract(x2).mod(P)
    return [x, slope.multiply(x1.subtract(x)).subtract(y1).mod(P)]
}
List pointMultiply(BigInteger scalar, List point) {
    // Fixed iteration count. BigInteger itself is NOT constant-time; see docs.
    BigInteger k = scalar.mod(ORDER)
    List result = null
    for (int bit = 255; bit >= 0; bit--) {
        result = pointAdd(result, result)
        if (k.testBit(bit)) result = pointAdd(result, point)
    }
    return result
}
String credentialString(Map register) {
    Map extra = register.extra_crypt instanceof Map ? register.extra_crypt : [:]
    if (!extra) return settings.tpapUsername + "/" + settings.tpapPassword
    check(extra.type == "password_shadow", "Unsupported password transform")
    check(extra.params?.passwd_id in [2, 4], "Unsupported password shadow mode")
    // Mode 4 consumes the local-control secret, provisioned as SHA-1 by Tapo.
    // Verified on S505D firmware 1.4.0; never trim or normalize the password.
    return hex(hash("SHA-1", utf8(settings.tpapPassword.toString())))
}
Map makeShare(Map register, byte[] userRandom, String credentials, BigInteger ephemeral) {
    check(register.cipher_suites == 1 && register.encryption == "aes_128_ccm", "Unsupported negotiated TPAP suite")
    check(register.iterations instanceof Number && register.iterations >= 1 && register.iterations <= 10000 && register.iterations == register.iterations.intValue(), "Unsupported PBKDF2 iterations")
    byte[] salt = unb64(register.dev_salt), devRandom = unb64(register.dev_random)
    check(userRandom.length == 32 && devRandom.length == 32 && salt.length > 0 && salt.length <= 64, "Invalid PAKE random or salt length")
    check(ephemeral.signum() > 0 && ephemeral < ORDER, "Invalid ephemeral scalar")
    byte[] derived = pbkdf2(utf8(credentials), salt, register.iterations as Integer, 80)
    BigInteger w = new BigInteger(1, slice(derived, 0, 40)).mod(ORDER)
    BigInteger h = new BigInteger(1, slice(derived, 40, 80)).mod(ORDER)
    List m = decodePoint(POINT_M.decodeHex()), n = decodePoint(POINT_N.decodeHex())
    List g = decodePoint(GENERATOR.decodeHex()), r = decodePoint(unb64(register.dev_share))
    List l = pointAdd(pointMultiply(ephemeral, g), pointMultiply(w, m))
    List wn = pointMultiply(w, n)
    List rp = pointAdd(r, wn == null ? null : [wn[0], P.subtract(wn[1]).mod(P)])
    check(rp != null, "Degenerate device PAKE share")
    byte[] lBytes = encodePoint(l), rBytes = encodePoint(r)
    byte[] context = hash("SHA-256", cat([utf8("PAKE V1"), userRandom, devRandom]))
    List fields = [context, new byte[0], new byte[0], encodePoint(m), encodePoint(n), lBytes, rBytes,
        encodePoint(pointMultiply(ephemeral, rp)), encodePoint(pointMultiply(h, rp)), encodeW(w)]
    byte[] transcriptHash = hash("SHA-256", cat(fields.collect { lengthPrefix(it) }))
    byte[] confirmationKeys = hkdf(transcriptHash, new byte[64], utf8("ConfirmationKeys"), 64)
    byte[] shared = hkdf(transcriptHash, new byte[32], utf8("SharedKey"), 32)
    return [shared: b64(shared), confirm: b64(hmac(slice(confirmationKeys, 32, 64), lBytes)),
        params: [sub_method: "pake_share", user_share: b64(lBytes), user_confirm: b64(hmac(slice(confirmationKeys, 0, 32), rBytes))]]
}
Map sessionKeys(byte[] shared) {
    return [key: b64(hkdf(shared, utf8("tp-kdf-salt-aes128-key"), utf8("tp-kdf-info-aes128-key"), 16)),
            nonce: b64(hkdf(shared, utf8("tp-kdf-salt-aes128-iv"), utf8("tp-kdf-info-aes128-iv"), 12))]
}
def certificate(String text) {
    check(text && text.length() <= 16384, "Missing or oversized DAC certificate")
    byte[] encoded = text.startsWith("-----BEGIN") ? utf8(text) : unb64(text)
    return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(encoded))
}
void verifyDac(Map reply, byte[] shared, byte[] nonce) {
    verifyDacWithRoot(reply, shared, nonce, certificate(ROOT_CA))
}
// Root is injectable only in offline tests; the driver always uses ROOT_CA above.
void verifyDacWithRoot(Map reply, byte[] shared, byte[] nonce, root) {
    check(reply.dac_ca instanceof String && reply.dac_proof instanceof String, "Device advertised DAC but omitted its proof")
    def leaf = certificate(reply.dac_ca)
    def issuer = reply.dac_ica ? certificate(reply.dac_ica as String) : root
    root.checkValidity(); issuer.checkValidity(); leaf.checkValidity()
    check(issuer.basicConstraints >= 0, "DAC issuer is not a CA")
    check(!issuer.keyUsage || issuer.keyUsage[5], "DAC issuer cannot sign certificates")
    check(!leaf.keyUsage || leaf.keyUsage[0], "DAC leaf cannot sign proofs")
    if (reply.dac_ica) {
        check(issuer.issuerX500Principal == root.subjectX500Principal, "DAC intermediate issuer mismatch")
        issuer.verify(root.publicKey)
    }
    check(leaf.issuerX500Principal == issuer.subjectX500Principal, "DAC issuer mismatch")
    leaf.verify(issuer.publicKey)
    check(leaf.publicKey.algorithm == "EC", "Unsupported DAC proof key")
    Signature verifier = Signature.getInstance("SHA256withECDSA")
    verifier.initVerify(leaf.publicKey)
    verifier.update(cat([shared, nonce]))
    check(verifier.verify(unb64(reply.dac_proof)), "Invalid DAC proof signature")
}
byte[] nonceFor(byte[] base, long seq) {
    check(base.length == 12, "Invalid CCM nonce")
    return cat([slice(base, 0, 8), u32(seq)])
}
byte[] binaryBody(Object body) {
    // Hubitat AsyncResponse encodes application/octet-stream as base64.
    return unb64(body)
}
byte[] decryptFrame(Map session, byte[] frame, long expectedSeq) {
    check(frame.length >= 20 && frame.length <= 65556, "Invalid secure response size")
    long seq = 0
    for (int i = 0; i < 4; i++) seq = (seq << 8) | (frame[i] & 255)
    check(seq == expectedSeq, "Unexpected response sequence (possible replay)")
    return ccmDecrypt(unb64(session.key), nonceFor(unb64(session.nonce), seq), slice(frame, 4, frame.length))
}

// AES-CCM, nonce=12, tag=16, no AAD, using standard AES blocks.
// Avoids a dependency on a CCM provider not available in stock Java.
Cipher aesBlockCipher(byte[] key) {
    check(key.length == 16, "Invalid AES-128 key length")
    Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"))
    return cipher
}
byte[] xorBytes(byte[] a, byte[] b) {
    check(a.length == b.length, "XOR length mismatch")
    byte[] out = new byte[a.length]
    for (int i = 0; i < a.length; i++) out[i] = (byte)((a[i] & 255) ^ (b[i] & 255))
    return out
}
byte[] ccmBlock(byte[] nonce, int flags, int number) {
    check(nonce.length == 12 && number >= 0 && number <= 0xffffff, "Invalid CCM block")
    return cat([bytes([flags]), nonce, bytes([number >> 16, number >> 8, number])])
}
byte[] ccmTag(Cipher cipher, byte[] nonce, byte[] plaintext) {
    check(plaintext.length <= 65536, "CCM payload too large")
    byte[] tag = cipher.doFinal(ccmBlock(nonce, 0x3a, plaintext.length))
    for (int offset = 0; offset < plaintext.length; offset += 16) {
        byte[] block = new byte[16]
        for (int i = 0; i < Math.min(16, plaintext.length - offset); i++) block[i] = plaintext[offset + i]
        tag = cipher.doFinal(xorBytes(tag, block))
    }
    return xorBytes(tag, cipher.doFinal(ccmBlock(nonce, 2, 0)))
}
byte[] ccmCtr(Cipher cipher, byte[] nonce, byte[] input) {
    byte[] output = new byte[input.length]
    for (int offset = 0; offset < input.length; offset += 16) {
        byte[] mask = cipher.doFinal(ccmBlock(nonce, 2, offset.intdiv(16) + 1))
        for (int i = 0; i < Math.min(16, input.length - offset); i++) output[offset + i] = (byte)((input[offset + i] & 255) ^ (mask[i] & 255))
    }
    return output
}
byte[] ccmEncrypt(byte[] key, byte[] nonce, byte[] plaintext) {
    Cipher cipher = aesBlockCipher(key)
    byte[] tag = ccmTag(cipher, nonce, plaintext)
    return cat([ccmCtr(cipher, nonce, plaintext), tag])
}
byte[] ccmDecrypt(byte[] key, byte[] nonce, byte[] combined) {
    check(combined.length >= 16 && combined.length <= 65552, "Invalid CCM ciphertext size")
    Cipher cipher = aesBlockCipher(key)
    byte[] plaintext = ccmCtr(cipher, nonce, slice(combined, 0, combined.length - 16))
    check(equalBytes(ccmTag(cipher, nonce, plaintext), slice(combined, combined.length - 16, combined.length)), "CCM authentication failed")
    return plaintext
}
