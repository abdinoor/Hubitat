import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import groovy.transform.Field
import hubitat.helper.HexUtils
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import org.codehaus.groovy.runtime.EncodingGroovyMethods

metadata {
    definition(name: 'Tuya LAN Device', namespace: 'tuya', author: 'Dan Abdinoor',
               singleThreaded: true, importUrl: 'https://raw.githubusercontent.com/abdinoor/Hubitat/refs/heads/master/tuya-lan-driver.groovy') {
        capability "Switch"
        capability "Refresh"
        capability "Switch Level"
        capability "Initialize"
        attribute "commsError", "string"
        attribute "lastError", "string"
        attribute "host", "string"
        attribute "port", "string"
        attribute "gwId", "string"
    }

    preferences {
        section {
            input name: 'gwId',
                    type: 'text',
                    title: 'Device ID',
                    required: true

            input name: 'localKey',
                    type: 'password',
                    title: 'Local Key',
                    required: true

            input name: 'host',
                    type: 'text',
                    title: 'Device IP Address',
                    required: true

            input name: 'port',
                    type: 'text',
                    title: 'Device Port',
                    defaultValue: '6668',
                    required: true

            input name: 'pollRefresh',
                    title: 'Polling Refresh in Seconds',
                    type: 'number',
                    required: true,
                    defaultValue: '60'

            input name: 'logEnable',
                    type: 'bool',
                    title: 'Enable debug logging',
                    required: false,
                    defaultValue: false

            input name: 'txtEnable',
                    type: 'bool',
                    title: 'Enable descriptionText logging',
                    required: false,
                    defaultValue: true
        }
    }
}

// Tuya command types
@Field static final int CONTROL             = 7
@Field static final int STATUS              = 8
@Field static final int HEART_BEAT          = 9
@Field static final int DP_QUERY            = 0x0a
@Field static final int PREFIX_55AA_VALUE   = 0x000055AA
@Field static final int SUFFIX              = 0x0000AA55


@Field static final String VERSION = "1.1.0"
@Field static final int MAX_FRAME_BYTES = 65536

def installed() { initialize() }
def updated() { initialize() }
def initialize() {
    unschedule()
    state.tuyaPending = null
    state.tuyaQueue = []
    state.tuyaRx = ""
    state.tuyaRxAt = 0
    state.remove("lastCommand")
    // Never reset the counter on reconfiguration: stale responses must not match.
    state.tuyaSerial = ((state.tuyaSerial ?: 0) as Long) + 1L
    try {
        String ip = (settings.host ?: getDataValue("host"))?.toString()?.trim()
        checkTuya(ip != null && ip ==~ /(?:\d{1,3}\.){3}\d{1,3}/ &&
            ip.tokenize(".").every { it.toInteger() <= 255 }, "Set a valid device IPv4 address")
        String id = (settings.gwId ?: getDataValue("gwId"))?.toString()
        checkTuya(id != null && id.length() > 0, "Set the device ID")
        int portValue = (settings.port ?: getDataValue("port") ?: "6668").toString().toInteger()
        checkTuya(portValue > 0 && portValue <= 65535, "Set a valid device port")
        keyBytes() // Validate without copying the key into data values or events.
        updateDataValue("host", ip)
        updateDataValue("port", portValue.toString())
        updateDataValue("gwId", id)
        updateDataValue("driverVersion", VERSION)
        updateDataValue("pollRefresh", Math.max(30, Math.min(3600, (settings.pollRefresh ?: 60) as Integer)).toString())
        // Legacy data-only configurations remain readable until preferences are supplied.
        if (settings.localKey) removeDataValue("localKey")
        sendEvent(name: "host", value: ip)
        sendEvent(name: "port", value: portValue.toString())
        sendEvent(name: "gwId", value: id)
        runIn(getRefreshSeconds(), "poll")
        refresh()
    } catch (Exception e) { failTuyaSafe(e) }
}
private byte[] keyBytes() {
    String key = (settings.localKey ?: getDataValue("localKey"))?.toString()
    checkTuya(key != null && key.getBytes("UTF-8").length == 16, "Set a 16-byte local key")
    return key.getBytes("UTF-8") // Do not trim passwords/keys.
}
private void checkTuya(boolean ok, String message) {
    if (!ok) throw new IllegalArgumentException("Tuya: " + message)
}
def on() { queueTuya(CONTROL, ["1": true]) }
def off() { queueTuya(CONTROL, ["1": false]) }
def setRelayState(onOff) { queueTuya(CONTROL, ["1": onOff ? true : false]) }
def setLevel(level, ramp = null, onTime = null) {
    try {
        checkTuya(level != null, "Set a level between 0 and 100")
        int value = Math.max(0, Math.min(100, (level as BigDecimal).intValue()))
        // Existing DP mapping: relay=1, brightness=2, 0..100% -> 0..1000.
        // Transition duration and onTime are not implemented.
        if (value == 0) off()
        else queueTuya(CONTROL, ["1": true, "2": value * 10])
    } catch (Exception e) { failTuyaSafe(e) }
}
def refresh() { queueTuya(DP_QUERY, [:]) }
def poll() {
    refresh()
    runIn(getRefreshSeconds(), "poll")
}
private void queueTuya(int command, Map dps) {
    List queue = state.tuyaQueue ?: []
    if (command == DP_QUERY && (state.tuyaPending || queue.any { it.command == DP_QUERY })) return
    if (queue.size() >= 16) { LOG.warn "Tuya queue full; command rejected"; return }
    queue << [command: command, dps: dps]
    state.tuyaQueue = queue
    drainTuyaQueue()
}
def drainTuyaQueue() {
    if (state.tuyaPending || !state.tuyaQueue) return
    try {
        List queue = state.tuyaQueue
        Map request = queue.remove(0)
        state.tuyaQueue = queue
        long serial = ((state.tuyaSerial ?: 0) as Long) + 1L
        state.tuyaSerial = serial
        state.tuyaPending = [id: serial, command: request.command, wanted: request.dps]
        state.tuyaRx = ""
        issueTuya(request.command as Integer, request.dps)
    } catch (Exception e) { failTuyaSafe(e) }
}
private void issueTuya(int command, Map dps) {
    long next = ((state.seqno ?: 0) as Long) + 1L
    // Positive signed sequence IDs, reserved before I/O. Wrap only between requests.
    if (next > Integer.MAX_VALUE || next < 1) next = 1L
    state.seqno = next
    Map pending = state.tuyaPending
    pending.seq = next
    pending.stage = command == CONTROL ? "control" : "query"
    state.tuyaPending = pending
    Map token = [id: pending.id, seq: next]
    runIn(12, "tuyaTimedOut", [data: token])
    String id = getDataValue("gwId")
    checkTuya(id != null && id.length() > 0, "Set the device ID")
    Map payload = [gwId: id, devId: id, uid: id, t: now().intdiv(1000).toString()]
    if (command == CONTROL) payload.dps = dps
    sendLanCmd(next as Integer, command, JsonOutput.toJson(payload))
}
def tuyaTimedOut(Map token) {
    if (state.tuyaPending?.id == token?.id && state.tuyaPending?.seq == token?.seq) {
        failTuya("Response timed out; pending commands discarded")
    }
}
private void failTuyaSafe(Exception e) {
    // Never log exceptions, raw packets, JSON or crypto inputs: they may contain secrets.
    String reason = e instanceof IllegalArgumentException && e.message?.startsWith("Tuya: ") ?
        e.message.substring(6) : e.class.simpleName + " during Tuya communication"
    failTuya(reason)
}
private void failTuya(String reason) {
    state.tuyaPending = null
    state.tuyaQueue = []
    state.tuyaRx = ""
    unschedule("tuyaTimedOut")
    sendEvent(name: "commsError", value: "true")
    sendEvent(name: "lastError", value: reason)
    LOG.warn reason + "; no automatic command replay"
}
def parse(message) {
    try {
        String chunk = parseMessage(message)
        if (!chunk) return
        List frames = splitTuyaFrames(chunk)
        for (String frame : frames) {
            Map decoded = extractPayload(frame.decodeHex())
            Map pending = state.tuyaPending
            boolean matches = pending && (decoded.seq == pending.seq ||
                (decoded.seq == 0 && decoded.command == STATUS))
            if (decoded.returnCode != 0) {
                if (matches) failTuya("Device rejected command (code " + decoded.returnCode + ")")
                continue
            }
            Map info = [:]
            byte[] payload = decoded.payloadBytes
            if (payload.length) {
                checkTuya(payload.length % 16 == 0, "Invalid encrypted payload length")
                info = new JsonSlurper().parseText(new String(decrypt(keyBytes(), payload), "UTF-8")) as Map
            }
            // Publish only validated device reports, including unsolicited status.
            if (info.dps instanceof Map) updateStatus(info)
            if (!matches) continue
            if (pending.stage == "control") {
                unschedule("tuyaTimedOut")
                // An ACK is not proof that switch/level changed. Query the actual state.
                issueTuya(DP_QUERY, [:])
            } else if (info.dps instanceof Map && (info.dps["1"] instanceof Boolean || info.dps["2"] instanceof Number)) {
                checkTuya((pending.wanted ?: [:]).every { k, v -> info.dps[k] == v },
                    "Command acknowledged but read-back did not match")
                unschedule("tuyaTimedOut")
                state.tuyaPending = null
                sendEvent(name: "commsError", value: "false")
                sendEvent(name: "lastError", value: "none")
                runInMillis(50, "drainTuyaQueue")
            }
        }
    } catch (Exception e) { failTuyaSafe(e) }
}
String parseMessage(String message) {
    if (!message) return null
    checkTuya(message.length() <= MAX_FRAME_BYTES * 6, "Oversized LAN response")
    if (message ==~ /(?i)[0-9a-f]+/ && message.length() % 2 == 0) return message.toLowerCase()
    def matcher = message =~ /(?:^|[,\s])payload:\s*([^,]+)/
    if (!matcher.find()) return null
    String body = matcher.group(1).trim()
    if (body ==~ /(?i)[0-9a-f]+/ && body.length() % 2 == 0) return body.toLowerCase()
    checkTuya(body ==~ /[A-Za-z0-9+\/]*={0,2}/ && body.length() % 4 == 0, "Invalid LAN payload encoding")
    byte[] raw = body.decodeBase64()
    // Hubitat RAW/HEX_STRING responses contain Base64-encoded ASCII hex.
    // Also accept raw binary Base64, but never guess a cipher payload's boundaries.
    String ascii = new String(raw, "ISO-8859-1")
    if (ascii ==~ /(?i)[0-9a-f]+/ && ascii.length() % 2 == 0) return ascii.toLowerCase()
    return raw.encodeHex().toString()
}
List<String> splitTuyaFrames(String chunk) {
    checkTuya(chunk != null && chunk.length() % 2 == 0 && chunk ==~ /(?i)[0-9a-f]*/, "Invalid hex response")
    String old = now() - ((state.tuyaRxAt ?: 0) as Long) <= 15000L ? (state.tuyaRx ?: "") : ""
    String buffer = old + chunk.toLowerCase()
    checkTuya(buffer.length() <= MAX_FRAME_BYTES * 4, "Receive buffer limit exceeded")
    state.tuyaRxAt = now()
    List<String> frames = []
    while (buffer) {
        int prefix = buffer.indexOf("000055aa")
        if (prefix < 0) {
            // Retain only a possible split prefix, not arbitrary orphan ciphertext.
            int keep = 0
            for (int n = 2; n <= 6 && n <= buffer.length(); n += 2) {
                if (buffer.endsWith("000055aa".substring(0, n))) keep = n
            }
            buffer = keep ? buffer.substring(buffer.length() - keep) : ""
            break
        }
        buffer = buffer.substring(prefix)
        if (buffer.length() < 32) break
        long length = Long.parseLong(buffer.substring(24, 32), 16)
        checkTuya(length >= 12 && length <= MAX_FRAME_BYTES - 16, "Invalid frame length")
        int fullLength = ((16 + length) * 2) as Integer
        if (buffer.length() < fullLength) break
        String frame = buffer.substring(0, fullLength)
        // Validate framing and CRC before yielding anything to decryption.
        extractPayload(frame.decodeHex())
        frames << frame
        buffer = buffer.substring(fullLength)
    }
    state.tuyaRx = buffer
    return frames
}
private byte[] byteSlice(byte[] value, int start, int end) {
    checkTuya(start >= 0 && end >= start && end <= value.length, "Invalid byte slice")
    byte[] out = new byte[end - start]
    for (int i = 0; i < out.length; i++) out[i] = value[start + i]
    return out
}
private long readUnsignedInt(byte[] value, int pos) {
    return ((value[pos] & 255L) << 24) | ((value[pos + 1] & 255L) << 16) |
        ((value[pos + 2] & 255L) << 8) | (value[pos + 3] & 255L)
}
Map extractPayload(byte[] frame) {
    checkTuya(frame != null && frame.length >= 28 && frame.length <= MAX_FRAME_BYTES, "Invalid frame size")
    checkTuya(readUnsignedInt(frame, 0) == PREFIX_55AA_VALUE, "Invalid frame prefix")
    checkTuya(readUnsignedInt(frame, 12) == frame.length - 16, "Frame length mismatch")
    checkTuya(readUnsignedInt(frame, frame.length - 4) == SUFFIX, "Invalid frame suffix")
    long expected = calculateCRC32(byteSlice(frame, 0, frame.length - 8)) & 0xffffffffL
    checkTuya(readUnsignedInt(frame, frame.length - 8) == expected, "CRC mismatch")
    int start = 20
    int end = frame.length - 8
    // Responses contain a four-byte return code, then an optional 15-byte 3.3 header.
    if (end - start >= 3 && frame[start] == 0x33 && frame[start + 1] == 0x2e && frame[start + 2] == 0x33) {
        checkTuya(end - start >= 15, "Truncated version header")
        start += 15
    }
    return [seq: readUnsignedInt(frame, 4), command: readUnsignedInt(frame, 8),
        returnCode: readUnsignedInt(frame, 16), payloadBytes: byteSlice(frame, start, end)]
}
String decryptPayload(String hex, byte[] key) {
    Map frame = extractPayload(hex.decodeHex())
    checkTuya(frame.returnCode == 0, "Device rejected command")
    byte[] payload = frame.payloadBytes
    if (!payload.length) return JsonOutput.toJson([returnCode: frame.returnCode])
    checkTuya(payload.length % 16 == 0, "Invalid encrypted payload length")
    return new String(decrypt(key, payload), "UTF-8")
}
def updateStatus(Map response) {
    Map dps = response.dps
    if (!(dps instanceof Map)) return
    if (dps["1"] instanceof Boolean) sendEvent(name: "switch", value: dps["1"] ? "on" : "off")
    if (dps["2"] instanceof Number) {
        checkTuya(dps["2"] >= 0 && dps["2"] <= 1000, "Invalid brightness report")
        sendEvent(name: "level", value: (dps["2"] / 10).intValue())
    }
}
def sendLanCmd(int seq, int command, String payload) {
    byte[] message = encodeMessage(seq, command, payload, keyBytes())
    def action = new hubitat.device.HubAction(HexUtils.byteArrayToHexString(message),
        hubitat.device.Protocol.LAN, [destinationAddress: getAddress(),
        type: hubitat.device.HubAction.Type.LAN_TYPE_RAW,
        encoding: hubitat.device.HubAction.Encoding.HEX_STRING,
        timeout: 10, parseWarning: true, ignoreResponse: false])
    // Let the caller report failure; never pretend a failed send succeeded.
    sendHubCommand(action)
    LOG.debug "Tuya request sent (command " + command + ", sequence " + seq + ")"
}
def getAddress() {
    String host = getDataValue("host")
    checkTuya(host != null && host ==~ /(?:\d{1,3}\.){3}\d{1,3}/ &&
        host.tokenize(".").every { it.toInteger() <= 255 }, "Set a valid device IPv4 address")
    int port = (getDataValue("port") ?: "6668").toInteger()
    checkTuya(port > 0 && port <= 65535, "Set a valid device port")
    return host + ":" + port
}
def getRefreshSeconds() {
    return Math.max(30, Math.min(3600, (getDataValue("pollRefresh") ?: "60").toInteger()))
}

/* -------------------------------------------------------
 * Encoding methods
 */
byte[] encodeMessage(int seqno, int cmd, String payload, byte[] localKey) {
    byte[] encrypted = encrypt(localKey, payload)

    if (cmd == DP_QUERY) {
        return packMessage(seqno, cmd, encrypted, localKey)
    }

    byte[] versionHeader = createVersionHeader()
    packMessage(seqno, cmd, versionHeader, encrypted, localKey)
}

/* add the 3.x header in 12 bytes, padded by null char */
byte[] createVersionHeader() {
    byte[] versionHeader = new byte[12];
    float version = 3.3
    byte[] versionBytes = version.toString().getBytes("ISO-8859-1")
    // Overwrite the first 4 bytes
    for (int i = 0; i < versionBytes.length; i++) {
        versionHeader[i] = versionBytes[i]
    }
    return versionHeader
}

/* Pack all the bytes into a message that can be sent to device */
byte[] packMessage(int seqno, int cmd, byte[] versionHeader, byte[] payload, byte[] localKey) {
    // Calculate message length
    int msgLen = 15 + payload.length + 8

    // Create full message excluding CRC and suffix
    int bufferLen = (4 * 4) + versionHeader.length + 3 + payload.length // prefix, seqno, cmd, msgLen, header, payload

    byte[] buffer = new byte[bufferLen]
    int pos = 0

    // Write prefix
    writeIntToBuffer(buffer, pos, PREFIX_55AA_VALUE)
    pos += 4

    // Write seqno
    writeIntToBuffer(buffer, pos, seqno)
    pos += 4

    // Write cmd
    writeIntToBuffer(buffer, pos, cmd)
    pos += 4

    // Write msgLen
    writeIntToBuffer(buffer, pos, msgLen)
    pos += 4

    // Write versionHeader manually
    for (int i = 0; i < versionHeader.length; i++) {
        buffer[pos++] = versionHeader[i]
    }
    pos = 31 // Pad remaining bytes up to position 31

    // Write payload manually
    for (int i = 0; i < payload.length; i++) {
        buffer[pos++] = payload[i]
    }

    // Calculate CRC on the buffer up to this point
    Integer crc = calculateCRC32(buffer)

    // Create final buffer with space for CRC and suffix
    byte[] finalBuffer = new byte[pos + 4 + 4]

    // Copy everything from the first buffer manually
    for (int i = 0; i < pos; i++) {
        finalBuffer[i] = buffer[i]
    }

    // Write CRC
    writeIntToBuffer(finalBuffer, pos, crc)
    pos += 4

    // Write suffix
    writeIntToBuffer(finalBuffer, pos, SUFFIX)

    return finalBuffer
}

/* Pack all the bytes into a message that can be sent to device */
byte[] packMessage(int seqno, int cmd, byte[] payload, byte[] localKey) {
    int msgLen = payload.length + 8

    // Create full message excluding CRC and suffix
    int bufferLen = 0
    bufferLen += Integer.BYTES * 4 // prefix, seqno, cmd, msglen
    bufferLen += payload.length

    byte[] buffer = new byte[bufferLen]
    int pos = 0

    // Write prefix
    writeIntToBuffer(buffer, pos, PREFIX_55AA_VALUE)
    pos += 4

    // Write seqno
    writeIntToBuffer(buffer, pos, seqno)
    pos += 4

    // Write cmd
    writeIntToBuffer(buffer, pos, cmd)
    pos += 4

    // Write msgLen
    writeIntToBuffer(buffer, pos, msgLen)
    pos += 4

    pos = 16 // Pad remaining bytes up to position 16

    // Write payload manually
    for (int i = 0; i < payload.length; i++) {
        buffer[pos++] = payload[i]
    }

    // Calculate CRC on the buffer up to this point
    Integer crc = calculateCRC32(buffer)

    // Create final buffer with space for CRC and suffix
    byte[] finalBuffer = new byte[pos + 4 + 4]

    // Copy everything from the first buffer manually
    for (int i = 0; i < pos; i++) {
        finalBuffer[i] = buffer[i]
    }

    // Write CRC
    writeIntToBuffer(finalBuffer, pos, crc)
    pos += 4

    // Write suffix
    writeIntToBuffer(finalBuffer, pos, SUFFIX)

    return finalBuffer
}

/* Helper method to write an integer to a byte array at a given position */
void writeIntToBuffer(byte[] buffer, int pos, int value) {
    buffer[pos] = (byte) ((value >> 24) & 0xFF)
    buffer[pos + 1] = (byte) ((value >> 16) & 0xFF)
    buffer[pos + 2] = (byte) ((value >> 8) & 0xFF)
    buffer[pos + 3] = (byte) (value & 0xFF)
}

/* CRC32 checksum calculation method */
Integer calculateCRC32(byte[] data) {
    int crc = 0xFFFFFFFF
    for (byte b : data) {
        crc ^= (b & 0xFF)
        for (int i = 0; i < 8; i++) {
            if ((crc & 1) != 0) {
                crc = (crc >>> 1) ^ 0xEDB88320
            } else {
                crc >>>= 1
            }
        }
    }
    return crc ^ 0xFFFFFFFF
}

/* encrypt the payload part of the message */
byte[] encrypt(byte[] key, String plaintext) {
    SecretKeySpec secretKey = new SecretKeySpec(key, "AES")

    // Create AES cipher instance in ECB mode
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)

    byte[] plainBytes = plaintext.getBytes("UTF-8")

    // Perform encryption
    cipher.doFinal(plainBytes)
}

/* decrypt the payload part of the response */
byte[] decrypt(byte[] key, byte[] encrypted) {
    checkTuya(encrypted.length > 0 && encrypted.length % 16 == 0, "Invalid encrypted payload length")

    SecretKeySpec secretKey = new SecretKeySpec(key, "AES")

    // Create AES cipher instance in ECB mode PKCS5Padding
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, secretKey)

    // Perform decryption
    cipher.doFinal(encrypted)
}

@Field private final Map LOG = [
    debug: { s -> if (settings.logEnable) log.debug(s) },
    warn: { s -> log.warn(s) }
].asImmutable()
