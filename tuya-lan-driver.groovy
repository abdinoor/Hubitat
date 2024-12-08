import com.hubitat.app.DeviceWrapper
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import groovy.transform.Field
import hubitat.helper.HexUtils
import hubitat.scheduling.AsyncResponse
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

metadata {
    definition(name: 'Tuya LAN Driver', namespace: 'tuya', author: 'Dan Abdinoor',
               importUrl: 'https://raw.githubusercontent.com/abdinoor/Hubitat/refs/heads/master/tuya-lan-driver.groovy') {
        capability "Switch"
        capability "Refresh"
        capability "Switch Level"
        capability "Change Level"
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
    def payload = $/{"gwId":"${gwId}","devId":"${gwId}","uid":"${gwId}","t":"${timestamp}","dps":{"1":${dps}}}/$
    sendCmd(CONTROL, payload)
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
    def payload = $/{"gwId":"${gwId}","devId":"${gwId}","uid":"${gwId}","t":"${timestamp}","dps":{"2":${level * 10}}}/$
    sendCmd(CONTROL, payload)
    sendEvent(name: "level", value: level)
    sendEvent(name: "switch", value: "on")
}

void refresh() {
    def gwId = getDataValue("gwId")
    if (logEnable) log.debug "refresh: [gwId: ${gwId}]"
    def timestamp = new Date().time.toString().substring(0, 10)
    def payload = $/{"gwId":"${gwId}","devId":"${gwId}","uid":"${gwId}","t":"${timestamp}"}/$
    sendCmd(DP_QUERY, payload)
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
    if (logEnable) log.debug "parse: message: ${message}"
    def jsonResponse = new JsonSlurper().parseText(message)
    if (logEnable) log.debug "parse: jsonResponse: ${jsonResponse}"
    // sendEvent(name: "level", value: level)
    // sendEvent(name: "switch", value: "on")
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

/* combine host IP address and port */
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
    SecretKeySpec secretKey = new SecretKeySpec(key, "AES")

    // Create AES cipher instance in ECB mode PKCS5Padding
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, secretKey)

    // Perform decryption
    cipher.doFinal(encrypted)
}

byte[] pad(byte[] data, int blockSize = 16) {
    if (data.length % blockSize == 0) {
        return data
    }

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

/* Unpack the message received from a device */
def unpackMessage(String received, byte[] localKey) {
    byte[] decodedBytes = received.getBytes("ISO-8859-1")

    // remove header, crc and suffix
    int from = (5 * 8)
    int to = decodedBytes.length - (2 * 8) - 1
    byte[] payloadBytes = decodedBytes[from..to]
    String payload = new String(payloadBytes, "ISO-8859-1")

    // decrypt
    payloadBytes = EncodingGroovyMethods.decodeHex(payload)
    byte[] decryptedBytes = decrypt(localKey, payloadBytes)
    String decrypted = new String(decryptedBytes, "ISO-8859-1")
    return decrypted
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
