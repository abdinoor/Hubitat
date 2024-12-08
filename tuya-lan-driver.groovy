import com.hubitat.app.DeviceWrapper
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import groovy.transform.Field
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.spec.SecretKeySpec
import javax.crypto.Cipher
import javax.crypto.Mac
import hubitat.helper.HexUtils
import hubitat.scheduling.AsyncResponse
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec

metadata {
    definition(name: 'Tuya LAN Driver', namespace: 'tuya', author: 'Dan Abdinoor') {
        capability "Switch"
        capability "Refresh"
        capability "Switch Level"
        capability "Change Level"
        command "setPollInterval", [[
            name: "Poll Interval in seconds",
            constraints: ["default", "1 second", "5 seconds", "10 seconds",
                          "15 seconds", "30 seconds", "1 minute", "5 minutes",
                          "10 minutes", "30 minutes"],
            type: "ENUM"]]
        attribute "connection", "string"
        attribute "commsError", "string"
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
                    defaultValue: true

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
    def updStatus = [:]

    updateDataValue("localKey", localKey)
    sendEvent(name: "localKey", value: localKey)
    updStatus << [localKey: localKey]

    updateDataValue("gwId", gwId)
    sendEvent(name: "gwId", value: gwId)
    updStatus << [gwId: gwId]

    updateDataValue("host", host)
    sendEvent(name: "host", value: host)
    updStatus << [host: host]

    updateDataValue("port", port)
    sendEvent(name: "port", value: port)
    updStatus << [port: port]

    if (logEnable) log.debug updStatus

    // refresh()
}

def on() {
    setRelayState(1)
}

def off() {
    setRelayState(0)
}

def setRelayState(onOff) {
    if (logEnable) log.debug "setRelayState: [switch: ${onOff}]"
    def timestamp = new Date().time.toString().substring(0, 10)
    def gwId = getDataValue("gwId")
    def dps = onOff ? "true" : "false"
    def cmd = $/{"gwId":"${gwId}","devId":"${gwId}","uid":"${gwId}","t":"${timestamp}","dps":{"1":${dps}}}/$
    sendCmd(cmd)
    sendEvent(name: "switch", value: (onOff) ? "on" : "off", type: "digital")
}

void setLevel(level, ramp = null, onTime = null ) {
    if (!level) {
        off()
        return
    }
    if (logEnable) log.debug "setLevel: [level: $level]"
    def timestamp = new Date().time.toString().substring(0, 10)
    def gwId = getDataValue("gwId")
    def cmd = $/{"gwId":"${gwId}","devId":"${gwId}","uid":"${gwId}","t":"${timestamp}","dps":{"2":${level * 10}}}/$
    sendCmd(cmd)
    sendEvent(name: "level", value: level)
    sendEvent(name: "switch", value: "on")
}

void refresh() {
    def gwId = getDataValue("gwId")
    if (logEnable) log.debug "refresh: [gwId: ${gwId}]"
    def timestamp = new Date().time.toString().substring(0, 10)
    def payload = $/{"gwId":"${gwId}","devId":"${gwId}","uid":"${gwId}","t":"${timestamp}"}/$
    sendCmd(DP_QUERY, payload)
    // sendEvent(name: "level", value: level)
    // sendEvent(name: "switch", value: "on")
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

// callback from hubitat
def parse(message) {
    if (logEnable) log.debug "parse: ${message}"
    // return createEvent(name: "switch", value: "off")
}

def sendLanCmd(int seqno, int command, String payload) {
    if (logEnable) log.debug "sendLanCmd: [IP: ${getAddress()}, payload: ${payload}]"

    byte[] message = encodeMessage(seqno, command, payload, getDataValue("localKey").getBytes())

    def myHubAction = new hubitat.device.HubAction(
        HexUtils.byteArrayToHexString(message),
        hubitat.device.Protocol.LAN,
        [
            destinationAddress: getAddress(),
            type: hubitat.device.HubAction.Type.LAN_TYPE_RAW,
            encoding: hubitat.device.HubAction.Encoding.HEX_STRING
        ])
    try {
        sendHubCommand(myHubAction)
    } catch (e) {
        log.warn "sendLanCmd: LAN Error = ${e}.\n\rNo retry on this error."
    }
}

def getAddress() {
    def ip = getDataValue("host")
    if (ip == null) log.warn "No IP address set for ${device}"
    def port = getDataValue("port")
    return "${ip}:${port}"
}


/* -------------------------------------------------------
 * Encoding methods
 */
byte[] encodeMessage(int seqno, int cmd, String payload, byte[] localKey) {
    byte[] encrypted = encrypt(getDataValue("localKey").getBytes(), payload.getBytes())
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
    int PREFIX_55AA_VALUE = 0x000055AA
    int SUFFIX = 0x0000AA55

    // Calculate message length
    int msgLen = 15 + payload.length + 8

    // Create full message excluding CRC and suffix
    int bufferLen = (4 * 4) + versionHeader.length + 3 + payload.length // prefix, seqno, cmd, msgLen, header, payload

    if (cmd == DP_QUERY) {
        msgLen -= 15
        bufferLen -= 15
    }

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

    if (cmd != DP_QUERY) {
        // Write versionHeader manually
        for (int i = 0; i < versionHeader.length; i++) {
            buffer[pos++] = versionHeader[i]
        }
        pos = 31 // Pad remaining bytes up to position 31
    } else {
        pos = 16 // Pad remaining bytes up to position 16
    }

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

// Helper method to write an integer to a byte array at a given position
void writeIntToBuffer(byte[] buffer, int pos, int value) {
    buffer[pos] = (byte) ((value >> 24) & 0xFF)
    buffer[pos + 1] = (byte) ((value >> 16) & 0xFF)
    buffer[pos + 2] = (byte) ((value >> 8) & 0xFF)
    buffer[pos + 3] = (byte) (value & 0xFF)
}

// CRC32 checksum calculation method
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

char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
        int v = bytes[j] & 0xFF;
        hexChars[j * 2] = HEX_ARRAY[v >>> 4];
        hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
    }
    return new String(hexChars);
}

/* encrypt the payload part of the message */
byte[] encrypt(byte[] key, byte[] raw, boolean padded = true) {
    if (padded) {
        raw = pad(raw, 16)
    }

    // Create AES cipher instance in ECB mode
    Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding")
    SecretKeySpec secretKey = new SecretKeySpec(key, "AES")

    cipher.init(Cipher.ENCRYPT_MODE, secretKey)

    // Perform encryption
    cipher.doFinal(raw)
}

byte[] pad(byte[] data, int blockSize = 16) {
    int paddingLength = blockSize - (data.length % blockSize)
    byte paddingByte = (byte) paddingLength
    byte[] paddedData = new byte[data.length + paddingLength]

    // Manually copy data to paddedData
    for (int i = 0; i < data.length; i++) {
        paddedData[i] = data[i]
    }

    // Fill padding bytes
    for (int i = data.length; i < paddedData.length; i++) {
        paddedData[i] = paddingByte
    }

    return paddedData
}

@Field private final Map LOG = [
        debug    : { s -> if (settings.logEnable == true) { log.debug(s) } },
        info     : { s -> log.info(s) },
        warn     : { s -> log.warn(s) },
        error    : { s -> log.error(s) },
        exception: { message, exception ->
            List<StackTraceElement> relevantEntries = exception.stackTrace.findAll { entry -> entry.className.startsWith('user_app') }
            Integer line = relevantEntries[0]?.lineNumber
            String method = relevantEntries[0]?.methodName
            log.error("${message}: ${exception} at line ${line} (${method})")
            if (settings.logEnable) {
                log.debug("App exception stack trace:\n${relevantEntries.join('\n')}")
            }
        }
].asImmutable()