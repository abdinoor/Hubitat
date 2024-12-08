import groovy.transform.Field
import org.codehaus.groovy.runtime.EncodingGroovyMethods

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

        byte[] encrypted = encrypt(getDataValue("localKey").getBytes(), cmd)

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
        def payload = /{"devId":"eb9612d77425380d2efeup","uid":"eb9612d77425380d2efeup","t":"1733026274","dps":{"1":true}}/

        int seqno = 1

        byte[] response = sendLanCmd(seqno, CONTROL, payload)
        String hex = bytesToHex(response)

        def expected = "000055aa000000010000000700000087332e33000000000000000000000000735879e92b4d4f2305721cb8528b2e2b39ad037276745189c833ad8c5fdda5b21fe8d4ab74047e6fa8a65e32b80cb5c9885e8cf0b3280224f051d0d9c680f672e1723748cca7f6e47fa3e19e09f3e7aa3bbc590ad2c7edec5303fcd363b077b51c464b29da353909f8e85cb3f30d06cf4d6349030000aa55"

        assertEquals(expected, hex)
    }

    public void testSendLanCmdOff() {
        def payload = /{"devId":"eb9612d77425380d2efeup","uid":"eb9612d77425380d2efeup","t":"1733026550","dps":{"1":false}}/

        int seqno = 2

        byte[] response = sendLanCmd(seqno, CONTROL, payload)
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

    public void testDecodePayload() {
        def response = [
            payload:"MDAwMDU1QUEwMDAwMDAwMTAwMDAwMDBBMDAwMDAwNEMwMDAwMDAwMDRBMkY4NDU5QUE5REFCREY4MjVBMkY3QkZERkUwODUyNzQwMzY3Q0Q4NDI3OTRERjNBNTY3QUMyMTU2RTJCM0YyQ0E1QjUzMjJCQjVENjczNjNCOEMyOThFODZCMDBCQjExRTdGMDA2OUIyQzgwODU1NzJDNzg0NkM1QTNEMDU1NkE5QTJCNjUwMDAwQUE1NQ==",
        ]

        String expected = "000055AA000000010000000A0000004C000000004A2F8459AA9DABDF825A2F7BFDFE0852740367CD842794DF3A567AC2156E2B3F2CA5B5322BB5D67363B8C298E86B00BB11E7F0069B2C8085572C7846C5A3D0556A9A2B650000AA55"

        byte[] decodedBytes = Base64.getDecoder().decode(response.payload)
        StringBuilder byteString = new StringBuilder();
        for (byte b : decodedBytes) {
            // Convert each byte to its character representation
            byteString.append((char) b);
        }

        String received = byteString.toString()
        assertEquals(expected, byteString.toString())
    }

    public void testDecodeAddress() {
        def response = [
            ip:'c0a805ca',
            port:'1a0c',
        ]
        assertEquals("192.168.5.202", decodeHost(response.ip))
        assertEquals("6668", decodePort(response.port))
    }

    public void testDecryptPayload() {
        String expected = '{"dps":{"1":false,"7":0},"type":"query","t":1733494551}'
        //  'ebaa0ec75b92164f67nc2a', address='192.168.5.202', local_key='9MZ4>xi7oPL?MCUf'
        //                                                       332e32000000000000000000000000
        //def response1 = "4a2f8459aa9dabdf825a2f7bfdfe0852740367cd842794df3a567ac2156e2b3f2ca5b5322bb5d67363b8c298e86b00bba0cc0160aa7608b4c96bcf7b611f7a00b163aa76f49fa2589e93cb0e33bf2476bf328be88b6ed89abb6fe84400751f03"
        //byte[] payloadBytes = response1.getBytes("ISO-8859-1")

        byte[] payloadBytes = new byte[] {
            0x4A, 0x2F, (byte) 0x84, 0x59, (byte) 0xAA, (byte) 0x9D, (byte) 0xAB, (byte) 0xDF,
            (byte) 0x82, 0x5A, 0x2F, 0x7B, (byte) 0xFD, (byte) 0xFE, 0x08, 0x52,
            (byte) 0xEC, (byte) 0x91, 0x42, 0x30, 0x73, (byte) 0x87, 0x10, 0x4C,
            0x0D, 0x5E, 0x1D, (byte) 0xD1, (byte) 0xFD, (byte) 0xA7, (byte) 0xDB, (byte) 0x9E,
            (byte) 0xB4, (byte) 0x81, (byte) 0x8C, 0x1C, (byte) 0xC1, (byte) 0xF7, (byte) 0xDE, 0x54,
            (byte) 0x91, (byte) 0xD2, (byte) 0xCB, 0x21, (byte) 0xCE, (byte) 0xC2, 0x01, 0x1D,
            (byte) 0xF3, 0x09, 0x4D, (byte) 0x97, 0x39, (byte) 0xDC, 0x17, 0x42,
            0x3C, (byte) 0xE3, (byte) 0xDE, 0x37, 0x5B, 0x79, (byte) 0xCA, (byte) 0x9E
        }

        // logger.info "payloadBytes is ${payloadBytes.length} bytes"

        def localKey = "9MZ4>xi7oPL?MCUf".getBytes()
        byte[] decryptedBytes = decrypt(localKey, payloadBytes)
        String payload = new String(decryptedBytes, "ISO-8859-1")
        assertEquals(payload, expected)
    }

    public void testUnpackPayload() {
        String received = "000055aa000000050000000a0000004c00000000135934a4f9978652c6b877497629133e92e560df6cfb9d824053b700d01b4f8e0fa022b6098bcb2293338c41cd55f971d0e6a078803290a258e496b1e2641aedff24b99a0000aa55"
        byte[] localKey = "X8#rf#xRr1dw)Bbn".getBytes()
        String payload = unpackMessage(received, localKey)
        String expected = '{"dps":{"1":false,"7":0,"14":"off","15":"none","18":""}}'
        assertEquals(expected, payload)
    }

    public void testDecrypt() {
        String expected = /{"devId":"eb9612d77425380d2efeup","uid":"eb9612d77425380d2efeup","t":"1732927690","dps":{"1":false}}/
        // logger.info "expected array: ${expected.getBytes()}"

        byte[] encrypted = encrypt(getDataValue("localKey").getBytes(), expected)
        // logger.info "enc string: ${new String(encrypted, "ISO-8859-1")}"
        // logger.info "enc array: ${encrypted.toString()}"
        // logger.info "enc string: ${encrypted.length}"

        byte[] decrypted = decrypt(getDataValue("localKey").getBytes(), encrypted)
        // logger.info "decrypted array: ${decrypted.toString()}"
        String payload = new String(decrypted, "ISO-8859-1")
        // logger.info "decrypted string: ${payload}"
        // logger.info "decrypted string: ${decrypted.length}"

        assertEquals(expected, payload)
    }

    public void testParseMessage() {
        String message = "index:00, mac:D8D668400385, ip:c0a805bd, port:1a0c, type:LAN_TYPE_RAW, payload:MDAwMDU1QUEwMDAwMDAwMTAwMDAwMDBBMDAwMDAwNEMwMDAwMDAwMDEzNTkzNEE0Rjk5Nzg2NTJDNkI4Nzc0OTc2MjkxMzNFOTJFNTYwREY2Q0ZCOUQ4MjQwNTNCNzAwRDAxQjRGOEUwRkEwMjJCNjA5OEJDQjIyOTMzMzhDNDFDRDU1Rjk3MUQwRTZBMDc4ODAzMjkwQTI1OEU0OTZCMUUyNjQxQUVENEU3QkM5NzAwMDAwQUE1NQ=="

        String field = "payload:"
        int loc = message.indexOf(field) + field.length()
        String payload = message.substring(loc, message.length())

        String expected = "000055AA000000010000000A0000004C00000000135934A4F9978652C6B877497629133E92E560DF6CFB9D824053B700D01B4F8E0FA022B6098BCB2293338C41CD55F971D0E6A078803290A258E496B1E2641AED4E7BC9700000AA55"

        byte[] decoded = payload.decodeBase64()
        String hex = new String(decoded, "ISO-8859-1")
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

    def sendLanCmd(int seqno, int cmd, String payload) {
        // logger.info "sendLanCmd: [IP: ${getAddress()}, payload: ${payload}]"

        byte[] message = encodeMessage(seqno, cmd, payload, getDataValue("localKey").getBytes())
        // logger.info payload

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
byte[] encrypt(byte[] key, String plaintext, boolean padded = true) {
    SecretKeySpec secretKey = new SecretKeySpec(key, "AES")

    // Create AES cipher instance in ECB mode
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)

    byte[] plainBytes = plaintext.getBytes()
    if (padded) {
        //plainBytes = pad(plainBytes)
    }

    // Perform encryption
    cipher.doFinal(plainBytes)
}

/* decrypt the payload part of the response */
byte[] decrypt(byte[] key, byte[] encrypted, boolean padded = true) {
    SecretKeySpec secretKey = new SecretKeySpec(key, "AES")

    // Create AES cipher instance in ECB mode PKCS5Padding
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, secretKey)

    if (padded) {
        // encrypted = pad(encrypted, 16)
    }

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

}
