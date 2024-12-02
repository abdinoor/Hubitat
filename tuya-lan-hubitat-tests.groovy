import java.nio.ByteBuffer
import groovy.transform.Field

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

import groovy.test.GroovyTestCase
import java.util.logging.Logger
import java.util.logging.Level


class EncryptTest extends GroovyTestCase {
    private static final Logger logger = Logger.getLogger(EncryptTest.class.getName());

    // Tuya command types
    static final int CONTROL             = 7
    static final int DP_QUERY            = 0x0a
    static final int PREFIX_55AA_VALUE   = 0x000055AA
    static final int SUFFIX              = 0x0000AA55

    public void testEncrypt() {
        def cmd = /{"devId":"eb9612d77425380d2efeup","uid":"eb9612d77425380d2efeup","t":"1732927690","dps":{"1":false}}/

        byte[] expected = [115, 88, 121, 233, 43, 77, 79, 35, 5, 114, 28, 184, 82, 139, 46, 43, 57, 173, 3, 114, 118, 116, 81, 137, 200, 51, 173, 140, 95, 221, 165, 178, 31, 232, 212, 171, 116, 4, 126, 111, 168, 166, 94, 50, 184, 12, 181, 201, 136, 94, 140, 240, 179, 40, 2, 36, 240, 81, 208, 217, 198, 128, 246, 114, 238, 197, 199, 205, 164, 128, 5, 116, 195, 123, 99, 168, 172, 236, 35, 136, 157, 202, 136, 13, 53, 198, 30, 128, 46, 165, 60, 175, 72, 108, 218, 254, 16, 248, 235, 75, 210, 216, 200, 160, 126, 228, 225, 17, 179, 97, 176, 179]

        byte[] encrypted = encrypt(getDataValue("localKey").getBytes(), cmd.getBytes())

        for(int i = 0; i < encrypted.length; i++)
        {
            byte b = encrypted[i]
            byte a = expected[i]
            // logger.info a + " vs. " + b
            assertEquals(a, b)
        }
    }

    public void testHeader() {
        byte[] expected = [51, 46, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        byte[] header = createVersionHeader()

        for(int i = 0; i < header.length; i++)
        {
            byte b = header[i]
            byte a = expected[i]
            // logger.info a + " vs. " + b
            assertEquals(a, b)
        }
    }

    public void testPackMessage() {
        def localKey = getDataValue("localKey").getBytes()

        byte[] encrypted = [115, 88, 121, 233, 43, 77, 79, 35, 5, 114, 28, 184, 82, 139, 46, 43, 57, 173, 3, 114, 118, 116, 81, 137, 200, 51, 173, 140, 95, 221, 165, 178, 31, 232, 212, 171, 116, 4, 126, 111, 168, 166, 94, 50, 184, 12, 181, 201, 136, 94, 140, 240, 179, 40, 2, 36, 240, 81, 208, 217, 198, 128, 246, 114, 238, 197, 199, 205, 164, 128, 5, 116, 195, 123, 99, 168, 172, 236, 35, 136, 157, 202, 136, 13, 53, 198, 30, 128, 46, 165, 60, 175, 72, 108, 218, 254, 16, 248, 235, 75, 210, 216, 200, 160, 126, 228, 225, 17, 179, 97, 176, 179]

        byte[] expected = [0, 0, 85, 170, 0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 135, 51, 46, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 115, 88, 121, 233, 43, 77, 79, 35, 5, 114, 28, 184, 82, 139, 46, 43, 57, 173, 3, 114, 118, 116, 81, 137, 200, 51, 173, 140, 95, 221, 165, 178, 31, 232, 212, 171, 116, 4, 126, 111, 168, 166, 94, 50, 184, 12, 181, 201, 136, 94, 140, 240, 179, 40, 2, 36, 240, 81, 208, 217, 198, 128, 246, 114, 238, 197, 199, 205, 164, 128, 5, 116, 195, 123, 99, 168, 172, 236, 35, 136, 157, 202, 136, 13, 53, 198, 30, 128, 46, 165, 60, 175, 72, 108, 218, 254, 16, 248, 235, 75, 210, 216, 200, 160, 126, 228, 225, 17, 179, 97, 176, 179, 90, 120, 89, 187, 0, 0, 170, 85]

        byte[] packed = packMessage(2, 7, createVersionHeader(), encrypted, localKey)

        for(int i = 0; i < expected.length; i++)
        {
            byte b = packed[i]
            byte a = expected[i]
            if (a != b) logger.info a + " vs. " + b + " idx=" + i
            assertEquals(a, b)
        }
    }


    public void testSendLanCmdOn() {
        def cmd = /{"devId":"eb9612d77425380d2efeup","uid":"eb9612d77425380d2efeup","t":"1733026274","dps":{"1":true}}/

        int seqno = 1

        byte[] response = sendLanCmd(seqno, CONTROL, cmd)
        String hex = bytesToHex(response)

        def expected = "000055aa000000010000000700000087332e33000000000000000000000000735879e92b4d4f2305721cb8528b2e2b39ad037276745189c833ad8c5fdda5b21fe8d4ab74047e6fa8a65e32b80cb5c9885e8cf0b3280224f051d0d9c680f672e1723748cca7f6e47fa3e19e09f3e7aa3bbc590ad2c7edec5303fcd363b077b51c464b29da353909f8e85cb3f30d06cf4d6349030000aa55"

        assertEquals(expected, hex)
    }

    public void testSendLanCmdOff() {
        def cmd = /{"devId":"eb9612d77425380d2efeup","uid":"eb9612d77425380d2efeup","t":"1733026550","dps":{"1":false}}/

        int seqno = 2

        byte[] response = sendLanCmd(seqno, CONTROL, cmd)
        String hex = bytesToHex(response)

        def expected = "000055aa000000020000000700000087332e33000000000000000000000000735879e92b4d4f2305721cb8528b2e2b39ad037276745189c833ad8c5fdda5b21fe8d4ab74047e6fa8a65e32b80cb5c9885e8cf0b3280224f051d0d9c680f6729dd41870e6e3fe0c5d8820ad623fb2969dca880d35c61e802ea53caf486cdafe10f8eb4bd2d8c8a07ee4e111b361b0b35a74b1e20000aa55"

        assertEquals(expected, hex)
    }

    public void testStatus() {
        String payload = /{"gwId":"eb9612d77425380d2efeup","devId":"eb9612d77425380d2efeup","uid":"eb9612d77425380d2efeup","t":"1733111179"}/

        int seqno = 2

        byte[] response = sendLanCmd(seqno, DP_QUERY, payload)
        String hex = bytesToHex(response)

        def expected = "000055aa000000020000000a000000884b267b5455dc0fb5563799cc85d4bc01885e8cf0b3280224f051d0d9c680f672487e659b4e77845d2e81b0506b5b671e39ad037276745189c833ad8c5fdda5b21fe8d4ab74047e6fa8a65e32b80cb5c9885e8cf0b3280224f051d0d9c680f6720680710f826d52300a1a6a30ae01525b70a1c51c682c50f1b145d347ced6c436ae22ed250000aa55"

        assertEquals(expected, hex)
    }


    /* -------------------------------------------------------
     * Helper methods
     */

    def setRelayState(onOff) {
        logger.info "setRelayState: [switch: ${onOff}]"
        def timestamp = new Date().time.toString().substring(0, 10)
        def gwId = getDataValue("gwId")
        def dps = onOff ? "true" : "false"
        def payload = $/{"gwId":"${gwId}","devId":"${gwId}","uid":"${gwId}","t":"${timestamp}","dps":{"1":${dps}}}/$
        sendCmd(CONTROL, payload)
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

def sendLanCmd(int seqno, int command, String payload) {
    logger.info "sendLanCmd: [IP: ${getAddress()}, payload: ${payload}]"

    byte[] message = encodeMessage(seqno, command, payload, getDataValue("localKey").getBytes())

    return message

    def myHubAction = [
        request,
        hubitat.device.Protocol.LAN,
        [
            destinationAddress: getAddress(),
            type: hubitat.device.HubAction.Type.LAN_TYPE_RAW,
            encoding: hubitat.device.HubAction.Encoding.HEX_STRING,
            timeout: 1,
            callback: "parse"
        ]]
    try {
        // logger.info "sendHubCommand: ${myHubAction}"
        sendHubCommand(myHubAction)
    } catch (e) {
        log.warn "sendLanCmd: LAN Error = ${e}.\n\rNo retry on this error."
    }
}

    def getDataValue(String name) {
        if (name == "host") return "192.168.5.189"
        if (name == "port") return "6668"
        if (name == "localKey") return "X8#rf#xRr1dw)Bbn"
        throw new Exception('no data value')
    }

    def getAddress() {
        def ip = getDataValue("host")
        if (ip == null) log.warn "No IP address set for ${device}"
        def port = getDataValue("port")
        return "${ip}:${port}"
    }

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
}
