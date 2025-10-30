import groovy.json.JsonSlurper
import groovy.transform.Field
import hubitat.helper.HexUtils
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import org.codehaus.groovy.runtime.EncodingGroovyMethods

metadata {
    definition(name: 'Tuya LAN Device', namespace: 'tuya', author: 'Dan Abdinoor',
               importUrl: 'https://raw.githubusercontent.com/abdinoor/Hubitat/refs/heads/master/tuya-lan-driver.groovy') {
        capability "Switch"
        capability "Refresh"
        capability "Switch Level"
        attribute "localKey", "string"
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
                    type: 'text',
                    title: 'Local Key',
                    required: true

            input name: 'host',
                    type: 'text',
                    title: 'Device IP Address',
                    required: true

            input name: 'port',
                    type: 'text',
                    title: 'Device Port',
                    defaultValue: '6668'
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


/* -------------------------------------------------------
 * Hubitat commands
 */

def installed() {
    def instStatus = installCommon()
    logInfo("installed: ${instStatus}")
    refresh()
}

/* called when device settings are saved */
def updated() {
    def logMsg = [:]

    updateAttribute("gwId", gwId)
    logMsg << [gwId: gwId]

    updateAttribute("localKey", localKey)
    logMsg << [localKey: localKey]

    updateAttribute("host", host)
    logMsg << [host: host]

    updateAttribute("port", port)
    logMsg << [port: port]

    updateAttribute("pollRefresh", pollRefresh.toString())
    logMsg << [pollRefresh: pollRefresh]
    runIn(getRefreshSeconds(), poll)

    LOG.desc "updated: ${logMsg}"

    refresh()
}

def updateAttribute(name, value) {
    updateDataValue(name, value)
    sendEvent(name: name, value: value)
}

def on() {
    setRelayState(1)
}

def off() {
    setRelayState(0)
}

/* Switch method */
def setRelayState(onOff) {
    LOG.desc "setRelayState: [switch: ${onOff}]"
    def timestamp = new Date().time.toString().substring(0, 10)
    def gwId = getDataValue("gwId")
    def dps = onOff ? "true" : "false"
    def payload = $/{"gwId":"${gwId}","devId":"${gwId}","uid":"${gwId}","t":"${timestamp}","dps":{"1":${dps}}}/$
    sendCmd(CONTROL, payload)
    sendEvent(name: "switch", value: (onOff) ? "on" : "off")
}

/* Dimmer method */
def setLevel(level, ramp = null, onTime = null ) {
    level = getLevel(level)
    def hundreds = level * 10  // levels are set in 100s 50pct = 500
    LOG.desc "setLevel: [level: $level]"
    def timestamp = new Date().time.toString().substring(0, 10)
    def gwId = getDataValue("gwId")
    def payload = $/{"gwId":"${gwId}","devId":"${gwId}","uid":"${gwId}","t":"${timestamp}","dps":{"1":true,"2":${hundreds}}}/$
    sendCmd(CONTROL, payload)
    sendEvent(name: "level", value: level)
    sendEvent(name: "switch", value: "on")
}

/*  */
def getLevel(level) {
    if (level != null && level >= 0 && level <= 100) {
        return level
    }

    def currValue = device.currentValue("level")
    LOG.warn "getLevel: Invalid level=${level}. Using level=${currValue}"
    return currValue
}

def refresh() {
    def gwId = getDataValue("gwId")
    LOG.debug "refresh: [gwId: ${gwId}]"
    def timestamp = new Date().time.toString().substring(0, 10)
    def payload = $/{"gwId":"${gwId}","devId":"${gwId}","uid":"${gwId}","t":"${timestamp}"}/$
    sendCmd(DP_QUERY, payload)
}

def poll() {
    runIn(getRefreshSeconds(), poll)
    refresh()
}

def sendCmd(int command, String payload) {
    int seqno = 1
    if (state.seqno != null) {
        seqno = state.seqno++
    }
    state.lastCommand = payload
    sendLanCmd(seqno, command, payload)
}

/* -------------------------------------------------------
 * Communication methods
 */

/* callback from hubitat */
def parse(message) {
    LOG.debug "parse: gwId:${getDataValue('gwId')} ${message}"
    try {
        String hex = parseMessage(message)
        if (hex == null) {
            return
        }
        List<String> frames = splitTuyaFrames(hex)
        if (frames == null) {
            return
        }
        frames.eachWithIndex { f, i ->
            LOG.debug "frame ${i}: ${f}"
            String payload = decryptPayload(frames[i], getDataValue("localKey").getBytes())
            LOG.debug "frame ${i}: ${payload}"
            updateStatus(payload)
        }
    } catch (e) {
        LOG.exception("parse", e)
    }
}

/* Parse the payload from device message received */
String parseMessage(String message) {
    LOG.debug "parseMessage: ${message}"
    if (message == null) {
        return null
    }

    String field = "payload:"
    int loc = message.indexOf(field) + field.length()

    String payload = message.substring(loc, message.length())
    if (payload.length() == 0) {
        return null
    }

    byte[] decoded = payload?.decodeBase64()
    return new String(decoded, "ISO-8859-1")
}

/**
 * Extract the encrypted payload (still AES-ECB, PKCS-padded) from a raw
 * Tuya-LAN frame supplied as a byte array.
 *
 * Layout we expect in bytes
 * ┌─────────────────────────────────────────────────────────────┐
 * │  0- 3 :  prefix 0x000055AA                                  │
 * │  4- 7 :  sequence number                                    │
 * │  8-11 :  command                                            │
 * │ 12-15 :  msgLen                                             │
 * │ 16-23 :  (reserved / padding used by some firmwares)        │
 * │ 24-39 :  optional 3.x version header (“3.3”, 12 bytes → 16) │
 * │  ..   :  encrypted JSON payload                             │
 * │  -8--5:  CRC32                                              │
 * │  -4--1:  suffix 0x0000AA55                                  │
 * └─────────────────────────────────────────────────────────────┘
 *
 * @param frameBytes    complete frame *including* prefix & suffix
 * @return Map with payloadBytes and cmdCode
 */
Map extractPayload(byte[] frameBytes) {
    if (!frameBytes) return null

    Map response = [payloadBytes: null, cmdCode: 0]
    int idx = 0
    int msgLen = 0

    /* checking for prefix */
    if (frameBytes.length >= 4 &&
        (frameBytes[0] & 0xFF) == 0x00 &&
        (frameBytes[1] & 0xFF) == 0x00 &&
        (frameBytes[2] & 0xFF) == 0x55 &&
        (frameBytes[3] & 0xFF) == 0xAA)
    {
        idx = 20  // index 20 is where version header could be
        msgLen = ((frameBytes[12] & 0xFF) << 24) |
                 ((frameBytes[13] & 0xFF) << 16) |
                 ((frameBytes[14] & 0xFF) << 8)  |
                 (frameBytes[15] & 0xFF)

        response.command = ((frameBytes[4] & 0xFF) << 24) |
                           ((frameBytes[5] & 0xFF) << 16) |
                           ((frameBytes[6] & 0xFF) << 8)  |
                           (frameBytes[7] & 0xFF)
    } else {
        int end = frameBytes.length - 8  // drop trailing CRC(4) + suffix(4) = 8 bytes
        response['payloadBytes'] = frameBytes[0..<end]
        return response
    }

    // 12-byte messages are unencrypted Return-codes
    if (msgLen == 12) {
        idx = 16 // where payload starts on these messages
        int end = frameBytes.length - 8  // drop CRC(4) + suffix(4) = 8 bytes
        response['payloadBytes'] = frameBytes[idx..<end]
        return response
    }

    /* if a 3.x version header (“3.3”) follows, skip its padded 16-byte block */
    if ((frameBytes[idx] & 0xFF) == 0x33 &&             // '3'
        (frameBytes[idx + 1] & 0xFF) == 0x2E) {         // '.'
        idx = 35
    }

    /* checking for suffix */
    if ((frameBytes[frameBytes.length - 4] & 0xFF) == 0x00 &&
        (frameBytes[frameBytes.length - 3] & 0xFF) == 0x00 &&
        (frameBytes[frameBytes.length - 2] & 0xFF) == 0xAA &&
        (frameBytes[frameBytes.length - 1] & 0xFF) == 0x55)
    {
        int end = frameBytes.length - 8  // drop CRC(4) + suffix(4) = 8 bytes
        response['payloadBytes'] = frameBytes[idx..<end]
        return response
    }

    response['payloadBytes'] = frameBytes[idx..<frameBytes.length]
    return response
}

String decryptPayload(String received, byte[] localKey) {
    byte[] decoded = EncodingGroovyMethods.decodeHex(received)
    Map response = extractPayload(decoded)
    byte[] payload = response['payloadBytes']

    LOG.debug "decryptPayload: [payload: ${payload.encodeHex().toString()}, bytes: ${payload.length}, key: ${new String(localKey)}]"

    // 4-byte messages are a Return-code and are not encrypted
    if (payload.length == 4) {
        return handleReturnCode(response)
    }

    if (payload.length % 16 != 0) {
        LOG.error "decryptPayload: payload length must be divisible by 16 [payload: ${payload.encodeHex().toString()}, bytes: ${payload.length}, key: ${new String(localKey)}]"
        return null
    }

    byte[] decryptedBytes = decrypt(localKey, payload)
    if (decryptedBytes == null) {
        LOG.error "unpackMessage: decryptedBytes is null [payload: ${payload}]"
        return null
    }
    String decrypted = new String(decryptedBytes, "ISO-8859-1")
    LOG.debug "decryptPayload: [decrypted: ${decrypted}, payload: ${payload.encodeHex().toString()}, bytes: ${payload.length}, key: ${new String(localKey)}]"
    return decrypted
}

/**
 * Split a concatenated Tuya-LAN hex stream into individual frame-hex strings.
 *
 * Behaviours handled
 * ───────────────────
 * 1. **Normal framing** – frames that start with “000055AA … 0000AA55 ”.
 * 2. **Orphan suffix**  – when “0000AA55” noise appears *before* the next prefix,
 *    it is skipped.
 * 3. **Initial partial frame** – if the stream *begins* with data that
 *    **doesn’t** have a prefix (a tail of an earlier transmission),
 *    that slice is kept as frame 0 and returned unchanged.
 *
 * @param hex full stream (upper/lower case accepted)
 * @return    List<String> with every discovered frame, in order of appearance
 */
List<String> splitTuyaFrames(String hex) {
    hex = hex.toLowerCase()
    final String PREFIX = "000055aa"
    final String SUFFIX = "0000aa55"

    List<String> frames = []

    /* ── handle possible leading partial frame ─────────────────────────────── */
    int firstPrefix = hex.indexOf(PREFIX)
    if (firstPrefix == -1) {                          // no prefixes at all
        if (hex) frames << hex                        // whole stream = single frame
        return frames
    }
    if (firstPrefix > 0) {                            // data *before* first prefix
        String partial = hex.substring(0, firstPrefix)
        frames << partial
    }

    /* ── iterative extraction of proper frames ────────────────────────────── */
    int cursor = firstPrefix
    int idx    = (frames.isEmpty() ? 0 : 1)

    while (cursor < hex.length()) {

        /* skip any orphan suffix(es) appearing before the next real prefix */
        int orphanSuffix = hex.indexOf(SUFFIX, cursor)
        int nextPrefix   = hex.indexOf(PREFIX, cursor)

        if (orphanSuffix != -1 && orphanSuffix < nextPrefix) {
            cursor = orphanSuffix + SUFFIX.length()
            continue
        }

        /* locate the prefix we will parse now */
        int start = nextPrefix
        if (start == -1) break                        // nothing further

        /* need at least the fixed 16-byte header to read msgLen */
        if (start + 32 > hex.length()) break

        int msgLen = Integer.parseUnsignedInt(
                hex.substring(start + 24, start + 32), 16)

        int frameHexLen = (16 + msgLen) * 2           // bytes → hex chars
        if (start + frameHexLen > hex.length()) {
            String truncated = hex.substring(start, hex.length())
            frames << truncated
            break                                     // incomplete trailing frame
        }

        String frameHex = hex.substring(start, start + frameHexLen)
        frames << frameHex
        idx++
        cursor = start + frameHexLen                  // jump past extracted frame
    }

    return frames
}

/**
 * Evaluate a 4-byte Tuya return-code.
 * rcBytes[3] is the actual code; the first three bytes are always 0.
 */
String handleReturnCode(Map response) {
    if (!response) return

    if (!response['payloadBytes'] instanceof Byte) {
        LOG.error "return-code must be a single byte"
        return null
    }

    int code = response['payloadBytes'][3] & 0xFF  // 0 = success, non-zero = failure

    if (code == 0) {
        LOG.info "Tuya command ${response.command} acknowledged (0x00)"
    } else {
        LOG.warn "Tuya command ${response.command} rejected (0x${String.format('%02X', code)})"
    }

    return """{"returnCode":${code}}"""
}

/* extract datapoints from json payload and update device status */
def updateStatus(payload) {
    if (payload == null) {
        LOG.warn "updateStatus: payload must not be null"
        return
    }


    def logMsg = [:]
    def response = new JsonSlurper().parseText(payload)
    if (!response.containsKey('dps')) {
        // no datapoints to update, probably a return-code message
        return
    }

    // handle the incoming data points (DPs)
    if (response.dps['1'] != null) {
        def onOff = (response.dps['1']) ? "on" : "off"
        if (onOff != device.currentValue("switch")) {
            sendEvent(name: "switch", value: onOff)
            logMsg << ["switch": onOff]
        }
    }
    if (response.dps['2'] != null) {
        def level = (int) (response.dps['2'] / 10)
        if (level != device.currentValue("level")) {
            sendEvent(name: "level", value: level)
            logMsg << [level: level]
        }
    }

    if (logMsg.size() > 0) {
        LOG.desc "status changed: ${logMsg}"
    }
}

def sendLanCmd(int seqno, int command, String payload) {
    LOG.debug "sendLanCmd: [IP: ${getAddress()}, payload: ${payload}]"

    byte[] message = encodeMessage(seqno, command, payload, getDataValue("localKey").getBytes())

    def myHubAction = new hubitat.device.HubAction(
        HexUtils.byteArrayToHexString(message),
        hubitat.device.Protocol.LAN,
        [
            destinationAddress: getAddress(),
            type: hubitat.device.HubAction.Type.LAN_TYPE_RAW,
            encoding: hubitat.device.HubAction.Encoding.HEX_STRING,
            timeout: 300,
            parseWarning: true,
            ignoreResponse: false
        ])
    try {
        sendHubCommand(myHubAction)
    } catch (e) {
        LOG.warn "sendLanCmd: LAN Error = ${e}.\n\rNo retry on this error."
    }
}

/* combine host IP address and port */
def getAddress() {
    def ip = getDataValue("host")
    if (ip == null) LOG.warn "No IP address set for ${device}"
    def port = getDataValue("port")
    return "${ip}:${port}"
}

/* get refresh rate or a default */
def getRefreshSeconds() {
    def seconds = getDataValue("pollRefresh")
    if (seconds == null) return 300
    return Integer.parseInt(getDataValue("pollRefresh"))
}


/* -------------------------------------------------------
 * Encoding methods
 */
byte[] encodeMessage(int seqno, int cmd, String payload, byte[] localKey) {
    byte[] encrypted = encrypt(getDataValue("localKey").getBytes(), payload)

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

    byte[] plainBytes = plaintext.getBytes()

    // Perform encryption
    cipher.doFinal(plainBytes)
}

/* decrypt the payload part of the response */
byte[] decrypt(byte[] key, byte[] encrypted) {
    if (encrypted.length % 16 != 0) {
        LOG.error "encrypted length must be divisible by 16 [length=${encrypted.length}]"
        return null
    }

    SecretKeySpec secretKey = new SecretKeySpec(key, "AES")

    // Create AES cipher instance in ECB mode PKCS5Padding
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, secretKey)

    // Perform decryption
    cipher.doFinal(encrypted)
}

String decodeHost(String host) {
    // Split the hex string into 4 octets (2 characters each)
    StringBuilder sb = new StringBuilder(15)
    sb.append(Integer.parseInt(host.substring(0, 2), 16))
    sb.append(".")
    sb.append(Integer.parseInt(host.substring(2, 4), 16))
    sb.append(".")
    sb.append(Integer.parseInt(host.substring(4, 6), 16))
    sb.append(".")
    sb.append(Integer.parseInt(host.substring(6, 8), 16))
    sb.toString()
}

String decodePort(String port) {
    Integer.parseInt(port.substring(0, 4), 16).toString()
}

@Field private final Map LOG = [
        debug    : { s -> if (settings.logEnable) { log.debug("${device.displayName}: ${s}") } },
        desc    : { s -> if (settings.txtEnable) { log.info("${device.displayName}: ${s}") } },
        info     : { s -> log.info("${device.displayName}: ${s}") },
        warn     : { s -> log.warn("${device.displayName}: ${s}") },
        error    : { s -> log.error("${device.displayName}: ${s}") },
        exception: { message, exception ->
            List<StackTraceElement> relevantEntries = exception.stackTrace.findAll { entry -> entry.className.startsWith('user_app') }
            Integer line = relevantEntries[0]?.lineNumber
            String method = relevantEntries[0]?.methodName
            log.error "<pre>${exception}<br><br>${message}: ${exception} at line ${line} (${method})<br><br>Stack trace:<br>${getStackTrace(exception) }"
            if (settings.logEnable) {
                log.debug("App exception stack trace:\n${relevantEntries.join('\n')}")
            }
        }
].asImmutable()
