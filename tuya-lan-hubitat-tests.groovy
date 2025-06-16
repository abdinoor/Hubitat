import groovy.transform.Field
import org.codehaus.groovy.runtime.EncodingGroovyMethods

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

import groovy.test.GroovyTestCase
import java.util.logging.Logger
import java.util.logging.Level
import groovy.json.JsonSlurper


class EncryptTest extends GroovyTestCase {
    private static final Logger logger = Logger.getLogger(EncryptTest.class.getName());

    // Tuya command types
    static final int CONTROL             = 7
    static final int DP_QUERY            = 0x0a
    static final int PREFIX_55AA_VALUE   = 0x000055AA
    static final int SUFFIX              = 0x0000AA55
    static final int HEADER              = 0x33

    public void testEncrypt() {
        def cmd = /{"devId":"eb9612d77425380d2efeup","uid":"eb9612d77425380d2efeup","t":"1732927690","dps":{"1":false}}/

        byte[] expected = [115, 88, 121, 233, 43, 77, 79, 35, 5, 114, 28, 184, 82, 139, 46, 43, 57, 173, 3, 114, 118, 116, 81, 137, 200, 51, 173, 140, 95, 221, 165, 178, 31, 232, 212, 171, 116, 4, 126, 111, 168, 166, 94, 50, 184, 12, 181, 201, 136, 94, 140, 240, 179, 40, 2, 36, 240, 81, 208, 217, 198, 128, 246, 114, 238, 197, 199, 205, 164, 128, 5, 116, 195, 123, 99, 168, 172, 236, 35, 136, 157, 202, 136, 13, 53, 198, 30, 128, 46, 165, 60, 175, 72, 108, 218, 254, 16, 248, 235, 75, 210, 216, 200, 160, 126, 228, 225, 17, 179, 97, 176, 179]

        byte[] encrypted = encrypt(getDataValue("localKey").getBytes(), cmd)

        for(int i = 0; i < encrypted.length; i++)
        {
            byte b = encrypted[i]
            byte a = expected[i]
            // LOG.debug a + " vs. " + b
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
            // LOG.debug a + " vs. " + b
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
            if (a != b) LOG.debug a + " vs. " + b + " idx=" + i
            assertEquals(a, b)
        }
    }

    public void testSendLanCmdOn() {
        def payload = /{"devId":"eb9612d77425380d2efeup","uid":"eb9612d77425380d2efeup","t":"1733026274","dps":{"1":true}}/

        int seqno = 1

        byte[] response = sendLanCmd(seqno, CONTROL, payload)
        String hex = EncodingGroovyMethods.encodeHex(response)

        def expected = "000055aa000000010000000700000087332e33000000000000000000000000735879e92b4d4f2305721cb8528b2e2b39ad037276745189c833ad8c5fdda5b21fe8d4ab74047e6fa8a65e32b80cb5c9885e8cf0b3280224f051d0d9c680f672e1723748cca7f6e47fa3e19e09f3e7aa3bbc590ad2c7edec5303fcd363b077b51c464b29da353909f8e85cb3f30d06cf4d6349030000aa55"

        assertEquals(expected, hex)
    }

    public void testSendLanCmdOff() {
        def payload = /{"devId":"eb9612d77425380d2efeup","uid":"eb9612d77425380d2efeup","t":"1733026550","dps":{"1":false}}/

        int seqno = 2

        byte[] response = sendLanCmd(seqno, CONTROL, payload)
        String hex = EncodingGroovyMethods.encodeHex(response)

        def expected = "000055aa000000020000000700000087332e33000000000000000000000000735879e92b4d4f2305721cb8528b2e2b39ad037276745189c833ad8c5fdda5b21fe8d4ab74047e6fa8a65e32b80cb5c9885e8cf0b3280224f051d0d9c680f6729dd41870e6e3fe0c5d8820ad623fb2969dca880d35c61e802ea53caf486cdafe10f8eb4bd2d8c8a07ee4e111b361b0b35a74b1e20000aa55"

        assertEquals(expected, hex)
    }

    public void testStatus() {
        String payload = /{"gwId":"eb9612d77425380d2efeup","devId":"eb9612d77425380d2efeup","uid":"eb9612d77425380d2efeup","t":"1733111179"}/

        int seqno = 2

        byte[] response = sendLanCmd(seqno, DP_QUERY, payload)
        String hex = EncodingGroovyMethods.encodeHex(response)

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

        // LOG.debug "payloadBytes is ${payloadBytes.length} bytes"

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
        // LOG.debug "expected array: ${expected.getBytes()}"

        byte[] encrypted = encrypt(getDataValue("localKey").getBytes(), expected)
        // LOG.debug "enc string: ${new String(encrypted, "ISO-8859-1")}"
        // LOG.debug "enc array: ${encrypted.toString()}"
        // LOG.debug "enc string: ${encrypted.length}"

        byte[] decrypted = decrypt(getDataValue("localKey").getBytes(), encrypted)
        // LOG.debug "decrypted array: ${decrypted.toString()}"
        String payload = new String(decrypted, "ISO-8859-1")
        // LOG.debug "decrypted string: ${payload}"
        // LOG.debug "decrypted string: ${decrypted.length}"

        assertEquals(expected, payload)
    }

    public void testHeaderErrorParse(){
        // this looks like it has a header but does not
        String hex = "000055AA000000010000000A0000004C00000000325182449C4C728679B63CA9DC330182AB78D7BAE9AA1CB8F75FDF72C7E492528E93E31B747A8E1CDDAF7F2952BA29271CCCB39F8AF59055520A39F4E4997394B4DD9C390000AA55"

        int loc = hex.indexOf("000055AA", 8)
        if (loc > 0) {
            hex = hex.substring(loc, hex.length())
        }

        String expected = "000055AA000000010000000A0000004C00000000325182449C4C728679B63CA9DC330182AB78D7BAE9AA1CB8F75FDF72C7E492528E93E31B747A8E1CDDAF7F2952BA29271CCCB39F8AF59055520A39F4E4997394B4DD9C390000AA55"
        assertEquals(expected, hex)

        byte[] localKey = "auVZSp}q*44HDEGC".getBytes()
        String payload = unpackMessage(hex, localKey)
        // LOG.debug payload
        expected = '{"dps":{"1":true,"2":620,"3":100,"4":"LED","102":0,"104":1}}'
        assertEquals(expected, payload)

        def response = new JsonSlurper().parseText(payload)
        // LOG.debug "${response.dps}"
        boolean onOff = response.dps['1']
        assertTrue(onOff)
    }

    public void testMod16Message1() {
        String hex = """325182449C4C728679B63CA9DC3301829913583B021F347B5D1CF4C3B65F315CC7CF0A35A03C3AB3D13B06262A3583CFEE9E6172CDEFDCE7CAF4F6A4D21CE2B5C565AD680000AA55000055AA00000000000000080000004B00000000332E3300000000000009B00000000107A32F20B9015D4E7A2997B740D699E6AD4397D8EB9627468D344175971AF491F15C4E70C9A37516353B10754CB7E27E"""

        byte[] localKey = "auVZSp}q*44HDEGC".getBytes()
        String payload = unpackMessage(hex, localKey)
        String expected = """{"dps":{"1":true},"type":"query","t":1749549507}"""
        assertEquals(expected, payload)
    }

    public void testMod16Message2() {
        String hex = """CD0EEC3A611014862B8CA115EA762F58AB261659CFD506D9B6C75DC8C364CB10D4BA1F0CF83E1D1E4A00EBC166FA37EFCD5E8F8C0000AA55000055AA00000000000000080000005B00000000332E33000000000000E65700000001CD0EEC3A611014862B8CA115EA762F58FA9FDB82D8B26C98E361163AD2D0A1F1B9852AA1EC588BB41FBD635980F4622A08026D4602E54483B68918F1B375C4D1"""

        byte[] localKey = "X8#rf#xRr1dw)Bbn".getBytes()
        String payload = unpackMessage(hex, localKey)
        String expected = """{"dps":{"1":true},"t":1749806243}"""
        assertEquals(expected, payload)
    }

    /* -------------------------------------------------------
     * Helper methods
     */

    def setRelayState(onOff) {
        LOG.debug "setRelayState: [switch: ${onOff}]"
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
        // LOG.debug "sendLanCmd: [IP: ${getAddress()}, payload: ${payload}]"

        byte[] message = encodeMessage(seqno, cmd, payload, getDataValue("localKey").getBytes())
        // LOG.debug payload

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
        // LOG.debug "sendHubCommand: ${myHubAction}"
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

/* encrypt the payload part of the message */
byte[] encrypt(byte[] key, String plaintext) {
    SecretKeySpec secretKey = new SecretKeySpec(key, "AES")

    // Create AES cipher instance in ECB mode
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)

    byte[] plainBytes = plaintext.getBytes()
    // plainBytes = pad(plainBytes)

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
String unpackMessage(String received, byte[] localKey) {
    if (received == null) {
        LOG.error "unpackMessage: received must not be null"
        return null
    }

    List<String> frames = splitTuyaFrames(received)
    LOG.debug "unpackMessage: parsed ${frames.size()} frames"
    return decryptFrame(frames[0], localKey)
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
 * @param frameBytes  complete frame *including* prefix & suffix
 * @return byte[]     encrypted payload portion only
 */
byte[] extractPayload(byte[] frameBytes) {
    if (!frameBytes) return null

    int idx = 0

    // if tuya prefix 0x000055AA remove prefix(4)+seq(4)+cmd(4)+msgLen(4)
    int msgLen = 0
    if (frameBytes.length >= 4 &&
        (frameBytes[0] & 0xFF) == 0x00 &&
        (frameBytes[1] & 0xFF) == 0x00 &&
        (frameBytes[2] & 0xFF) == 0x55 &&
        (frameBytes[3] & 0xFF) == 0xAA)
    {
        idx += 4 * 4
        msgLen = ((frameBytes[12] & 0xFF) << 24) |
                 ((frameBytes[13] & 0xFF) << 16) |
                 ((frameBytes[14] & 0xFF) << 8)  |
                 (frameBytes[15] & 0xFF)
    }

    if (msgLen > 0) {
        int modLen = msgLen / 16
        modLen = modLen * 16
        int endPos = frameBytes.length - 4 - 4 // exclude suffix(4) and crc(4)
        int startPos = endPos - modLen
        byte[] section =  frameBytes[startPos..<endPos]
        LOG.debug "section: [section: ${section.encodeHex().toString()}, bytes: ${section.length}, key: ${}]"

        if (section.length != modLen) return null

        return section
    }

    // Bytes 16-23 sit between the fixed 16-byte header and the first AES block.
    // Firmware uses them to preserve 16-byte alignment before encryption starts.
    // idx += 4

    /* if a 3.x version header (“3.3”) follows, skip its padded 16-byte block */
    if (frameBytes.length >= idx + 16 &&
        (frameBytes[idx] & 0xFF) == 0x33 &&             // '3'
        (frameBytes[idx + 1] & 0xFF) == 0x2E) {         // '.'
        idx += 16
        LOG.debug "THE 3X VERSION HEADER IS HERE"
    }

    /* drop trailing CRC(4) + suffix(4) = 8 bytes */
    int end = frameBytes.length - 8
    if (end <= idx) return null  // malformed/truncated

    return frameBytes[idx..<end]
}

String decryptFrame(String received, byte[] localKey) {
    byte[] decoded = EncodingGroovyMethods.decodeHex(received)
    byte[] payload = extractPayload(decoded)

    LOG.debug "decryptFrame: [payload: ${payload.encodeHex().toString()}, bytes: ${payload.length}, key: ${new String(localKey)}]"

    if (payload.length % 16 != 0) {
        LOG.error "decryptFrame: payload length must be divisible by 16 [payload: ${payload.encodeHex().toString()}, bytes: ${payload.length}, key: ${new String(localKey)}]"
        return null
    }

    byte[] decryptedBytes = decrypt(localKey, payload)
    if (decryptedBytes == null) {
        LOG.error "unpackMessage: decryptedBytes is null [payload: ${payload}]"
        return null
    }
    String decrypted = new String(decryptedBytes, "ISO-8859-1")
    LOG.debug "decryptFrame: [decrypted: ${decrypted}, payload: ${payload.encodeHex().toString()}, bytes: ${payload.length}, key: ${new String(localKey)}]"
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
        // LOG.debug "initial partial frame detected bytes=${partial.length() / 2}"
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
            // LOG.debug "orphan suffix at ${orphanSuffix}; skipping"
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
            // LOG.debug "truncated frame from ${start}; expected ${frameHexLen} hex chars"
            break                                     // incomplete trailing frame
        }

        String frameHex = hex.substring(start, start + frameHexLen)
        frames << frameHex
        // LOG.debug "frame ${idx} start=${start} bytes=${frameHexLen / 2} msgLen=${msgLen}"
        idx++
        cursor = start + frameHexLen                  // jump past extracted frame
    }

    return frames
}



String decodeHost(String host) {
    // Split the hex string into 4 octets (2 characters each)
    StringBuilder sb = new StringBuilder(15)
    sb.append(Integer.parseInt(host?.substring(0, 2), 16))
    sb.append(".")
    sb.append(Integer.parseInt(host?.substring(2, 4), 16))
    sb.append(".")
    sb.append(Integer.parseInt(host?.substring(4, 6), 16))
    sb.append(".")
    sb.append(Integer.parseInt(host?.substring(6, 8), 16))
    sb.toString()
}

String decodePort(String port) {
    Integer.parseInt(port?.substring(0, 4), 16).toString()
}

private final Map LOG = [
        debug    : { s -> logger.info(s) },
        info     : { s -> logger.info(s) },
        warn     : { s -> logger.info(s) },
        error    : { s -> logger.info(s) }
    ].asImmutable()

}
