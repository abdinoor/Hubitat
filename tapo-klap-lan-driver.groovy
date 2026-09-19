import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import groovy.transform.Field
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

metadata {
	definition (name: "Tapo KLAP LAN Device",
				namespace: "tapo",
				author: "Dan Abdinoor",
                singleThreaded: true,
				importUrl: 'https://raw.githubusercontent.com/abdinoor/Hubitat/refs/heads/master/tapo-klap-lan-driver.groovy'
			   ) {
        capability "Switch"
        capability "SwitchLevel"
        capability "Refresh"
        capability "Initialize"
        command "resetSession"
        attribute "lastError", "string"
		attribute "connection", "string"
		attribute "commsError", "string"
		attribute "deviceIP", "string"
	}

	preferences {
		input ("txtEnable", "bool",
			   title: "Enable descriptionText logging",
			   defaultValue: true)
		input name: 'logEnable',
                    type: 'bool',
                    title: 'Enable debug logging',
                    required: false,
                    defaultValue: false
		input ("manualIp", "string",
			   title: "Device IP Address",
			   defaultValue: getDataValue("deviceIP"))
        input name: 'pollRefresh',
                title: 'Polling Refresh in Seconds',
                type: 'number',
                required: true,
                defaultValue: '300'
        input name: 'klapUsername',
                type: 'string',
                title: 'TP-Link account username',
                required: true
        input name: 'klapPassword',
                type: 'password',
                title: 'TP-Link account password',
                required: true
	}
}

@Field static final String VERSION = "1.1.0"

def installed() { updated() }
def initialize() { updated() }
def resetSession() { updated() }

def updated() {
    unschedule()
    state.klapActive = null
    state.klapQueue = []
    state.klapSession = null
    state.klapHandshake = null
    state.klapSerial = ((state.klapSerial ?: 0) as Long) + 1L
    state.klapRetryAfter = 0
    state.klapAuthBlocked = false
    state.remove("deviceStatus")
    state.errorCount = 0
    updateDataValue("driverVersion", VERSION)
    sendEvent(name: "connection", value: "LAN")
    try {
        // Persist the corrected address BEFORE any request is queued.
        String host = validateKlapHost(settings.manualIp ?: getDataValue("deviceIP"))
        updateDataValue("deviceIP", host)
        sendEvent(name: "deviceIP", value: host)
        updateDataValue("pollRefresh", Math.max(30, Math.min(3600, (settings.pollRefresh ?: 300) as Integer)).toString())
        refresh()
        runIn(getRefreshSeconds(), "poll")
    } catch (Exception e) { klapFailSafe(e) }
}
def refresh() { sendKlapRequest("get_device_info", [:]) }
def poll() {
    refresh()
    runIn(getRefreshSeconds(), "poll")
}
private String validateKlapHost(Object value) {
    String host = value?.toString()?.trim()
    klapCheck(host != null && host ==~ /(?:\d{1,3}\.){3}\d{1,3}/ &&
        host.tokenize(".").every { it.toInteger() <= 255 }, "Set a valid device IPv4 address")
    return host
}

/**
HELPER METHODS
*/

def listAttributes() {
	def attrs = device.getSupportedAttributes()
	def attrList = [:]
	attrs.each {
		def val = device.currentValue("${it}")
		attrList << ["${it}": val]
	}
	LOG.debug "Attributes: ${attrList}"
}

def getRefreshSeconds() {
	/* get refresh rate or a default */
    def seconds = getDataValue("pollRefresh")
    if (seconds == null) return 300
    return Math.max(30, Math.min(3600, Integer.parseInt(seconds)))
}

def getDeviceAddr() {
	return getDataValue("deviceIP")
}

def updateSwitchState(status) {
	LOG.debug "Updating switch/level from device read-back"
	if (status.device_on != null) {
		String switchVal = status.device_on ? "on" : "off"
		if (switchVal != device.currentValue("switch")) {
			sendEvent(name: "switch", value: switchVal, descriptionText: "${device.displayName} switch is ${switchVal}")
		}
	}
	if (status.brightness != null) {
		Integer levelValue = status.brightness as Integer
		if (levelValue != device.currentValue("level")) {
			sendEvent(name: "level", value: levelValue, descriptionText: "${device.displayName} level is ${levelValue}")
		}
	}
}

def setCommsError(status) {
	if (!status) {
		sendEvent(name: "commsError", value: "false")
		state.errorCount = 0
	} else {
		sendEvent(name: "commsError", value: "true")
		return "commsErrorSet"
	}
}

// Switch capability commands ------------------------------------------------

def on() { sendKlapRequest("set_device_info", [device_on: true]) }
def off() { sendKlapRequest("set_device_info", [device_on: false]) }
def setLevel(level, duration = null) {
    int value = Math.max(0, Math.min(100, (level as BigDecimal).intValue()))
    // Transition duration is not implemented. Zero means off, not brightness 0.
    if (value == 0) off()
    else sendKlapRequest("set_device_info", [device_on: true, brightness: value])
}

// ============================================================================
// KLAP Protocol Implementation
// ============================================================================

private Map getKlapCredentials() {
	String username = settings?.klapUsername?.trim()
	String password = settings?.klapPassword?.toString()
	if (!username || !password) {
		LOG.warn "KLAP credentials not configured"
		return null
	}
	return [username: username, password: password]
}

private String getTerminalUuid() {
	String uuid = getDataValue("terminalUUID")
	if (!uuid) {
		uuid = generateTerminalUuid()
		updateDataValue("terminalUUID", uuid)
		LOG.debug "getTerminalUuid: generated new terminal UUID ${uuid}"
	}
	return uuid
}

private String generateTerminalUuid() {
	def hexChars = "0123456789abcdef"
	def rng = new SecureRandom()
	List<Integer> segments = [8, 4, 4, 4, 12]
	List<String> parts = []
	segments.each { len ->
		StringBuilder sb = new StringBuilder()
		len.times {
			sb.append(hexChars.charAt(rng.nextInt(hexChars.length())))
		}
		parts << sb.toString()
	}
	return parts.join("-")
}

private Map getKlapSession() {
	if (!(state.klapSession instanceof Map)) {
		state.klapSession = [:]
	}
	return state.klapSession
}

private byte[] klapComputeAuthHash(String username, String password, boolean useV2) {
	if (useV2) {
		// V2: SHA256(SHA1(username) + SHA1(password))
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1")
		byte[] usernameSha1 = sha1.digest(username.getBytes("UTF-8"))
		sha1.reset()
		byte[] passwordSha1 = sha1.digest(password.getBytes("UTF-8"))
		
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256")
		sha256.update(usernameSha1)
		return sha256.digest(passwordSha1)
	} else {
		// V1: md5(md5(username) + md5(password))
		MessageDigest md5 = MessageDigest.getInstance("MD5")
		byte[] usernameMd5 = md5.digest(username.getBytes("UTF-8"))
		md5.reset()
		byte[] passwordMd5 = md5.digest(password.getBytes("UTF-8"))
		
		md5.reset()
		md5.update(usernameMd5)
		return md5.digest(passwordMd5)
	}
}

private byte[] klapHandshake1Hash(byte[] localSeed, byte[] remoteSeed, byte[] authHash, boolean useV2) {
	MessageDigest sha256 = MessageDigest.getInstance("SHA-256")
	if (useV2) {
		sha256.update(localSeed)
		sha256.update(remoteSeed)
		sha256.update(authHash)
	} else {
		sha256.update(localSeed)
		sha256.update(authHash)
	}
	return sha256.digest()
}

private byte[] klapHandshake2Hash(byte[] localSeed, byte[] remoteSeed, byte[] authHash, boolean useV2) {
	MessageDigest sha256 = MessageDigest.getInstance("SHA-256")
	if (useV2) {
		sha256.update(remoteSeed)
		sha256.update(localSeed)
		sha256.update(authHash)
	} else {
		sha256.update(remoteSeed)
		sha256.update(authHash)
	}
	return sha256.digest()
}

private Map getDefaultCredentials() {
	return [
		"KASA": ["kasa@tp-link.net", "kasaSetup"],
		"KASACAMERA": ["admin", "21232f297a57a5a743894a0e4a801fc3"],
		"TAPO": ["test@tp-link.net", "test"],
		"TAPOCAMERA": ["admin", "admin"]
	]
}

private String extractKlapCookie(def headers) {
	String cookieHeader = null
	if (!headers) return null
	
	// Try different ways to access the Set-Cookie header
	// Hubitat uses HeadersDecorator which may support Map-like access or method calls
	try {
		// Try as Map first
		if (headers instanceof Map) {
			headers.each { key, value ->
				if (key?.toString()?.toLowerCase() == 'set-cookie') {
					if (value instanceof List && value.size() > 0) {
						cookieHeader = value[0]?.toString()
					} else if (value) {
						cookieHeader = value.toString()
					}
				}
			}
		} else {
			// Try accessing via different header name variations
			for (String headerName : ['set-cookie', 'Set-Cookie', 'SET-COOKIE']) {
				try {
					def value = headers[headerName]
					if (value) {
						if (value instanceof List && value.size() > 0) {
							cookieHeader = value[0]?.toString()
						} else {
							cookieHeader = value.toString()
						}
						break
					}
				} catch (Exception e) {
					// Try next variation
				}
			}
			
			// If still not found, try iterating if possible
			if (!cookieHeader && headers.respondsTo('each')) {
				headers.each { key, value ->
					if (key?.toString()?.toLowerCase() == 'set-cookie') {
						if (value instanceof List && value.size() > 0) {
							cookieHeader = value[0]?.toString()
						} else if (value) {
							cookieHeader = value.toString()
						}
					}
				}
			}
		}
	} catch (Exception e) {
		LOG.warn "extractKlapCookie: could not read response headers"
		return null
	}
	
	if (!cookieHeader) return null
	
	// Extract cookie value (format: "Set-Cookie: TP_SESSIONID=..." or just "TP_SESSIONID=...")
	if (cookieHeader.contains(':')) {
		cookieHeader = cookieHeader.split(':', 2)[1]
	}
	if (cookieHeader.contains(';')) {
		cookieHeader = cookieHeader.split(';')[0]
	}
	
	String cookie = cookieHeader.trim()
	
	// Ensure cookie is just the value, not "Cookie: value"
	if (cookie.startsWith("Cookie:")) {
		cookie = cookie.substring(7).trim()
	}
	
	return cookie
}

private List klapFindMatchingAuthHash(byte[] localSeed, byte[] remoteSeed, byte[] serverHash, String username, String password) {
	// Try both V1 and V2 for each credential set
	def credentialSets = [
		["user", username, password]
	]
	
	getDefaultCredentials().each { key, creds ->
		credentialSets << [key, creds[0], creds[1]]
	}
	
	credentialSets << ["blank", "", ""]
	
	// Try V1 first, then V2
	for (boolean useV2 : [false, true]) {
		for (def credSet : credentialSets) {
			String credName = credSet[0]
			String un = credSet[1]
			String pw = credSet[2]
			
			byte[] authHash = klapComputeAuthHash(un, pw, useV2)
			byte[] expectedHash = klapHandshake1Hash(localSeed, remoteSeed, authHash, useV2)
			
			boolean matches = (serverHash.length == expectedHash.length)
			if (matches) {
				for (int i = 0; i < serverHash.length; i++) {
					if (serverHash[i] != expectedHash[i]) {
						matches = false
						break
					}
				}
			}
			if (matches) {
				return [authHash, useV2]
			}
		}
	}
	
	return null
}

private void klapDeriveSessionKeys(byte[] localSeed, byte[] remoteSeed, byte[] authHash) {
	Map session = getKlapSession()
	
	// Key derivation: SHA256("lsk" + local_seed + remote_seed + auth_hash)[:16]
	MessageDigest sha256 = MessageDigest.getInstance("SHA-256")
	sha256.update("lsk".getBytes("UTF-8"))
	sha256.update(localSeed)
	sha256.update(remoteSeed)
	sha256.update(authHash)
	byte[] keyHash = sha256.digest()
	byte[] aesKey = new byte[16]
	for (int i = 0; i < 16; i++) {
		aesKey[i] = keyHash[i]
	}
	
	// IV derivation: SHA256("iv" + local_seed + remote_seed + auth_hash)
	sha256.reset()
	sha256.update("iv".getBytes("UTF-8"))
	sha256.update(localSeed)
	sha256.update(remoteSeed)
	sha256.update(authHash)
	byte[] fullIv = sha256.digest()
	byte[] aesIvBase = new byte[12]
	for (int i = 0; i < 12; i++) {
		aesIvBase[i] = fullIv[i]
	}
	
	// Last 4 bytes = initial sequence number (signed big-endian)
	byte[] seqBytes = new byte[4]
	for (int i = 0; i < 4; i++) {
		seqBytes[i] = fullIv[i + 28]
	}
	int seq = ((seqBytes[0] & 0xFF) << 24) | 
	          ((seqBytes[1] & 0xFF) << 16) | 
	          ((seqBytes[2] & 0xFF) << 8) | 
	          (seqBytes[3] & 0xFF)
	if (seq > 0x7FFFFFFF) {
		seq = seq - 0x100000000
	}
	
	// Signature derivation: SHA256("ldk" + local_seed + remote_seed + auth_hash)[:28]
	sha256.reset()
	sha256.update("ldk".getBytes("UTF-8"))
	sha256.update(localSeed)
	sha256.update(remoteSeed)
	sha256.update(authHash)
	byte[] sigHash = sha256.digest()
	byte[] signature = new byte[28]
	for (int i = 0; i < 28; i++) {
		signature[i] = sigHash[i]
	}
	
	session.aesKey = aesKey.encodeBase64().toString()
	session.aesIvBase = aesIvBase.encodeBase64().toString()
	session.signature = signature.encodeBase64().toString()
	session.seq = seq
    session.format = 2
    state.klapSession = session
}

private List klapEncrypt(byte[] plaintext) {
	Map session = getKlapSession()
	byte[] aesKey = session.aesKey.decodeBase64()
	byte[] aesIvBase = session.aesIvBase.decodeBase64()
	byte[] signature = session.signature.decodeBase64()
	int seq = session.seq ?: 0
	
	if (!aesKey || !aesIvBase || !signature) {
		throw new IllegalStateException("AES key/IV not available")
	}
	
	// Never wrap a sequence in an existing session.
    klapCheck(seq < Integer.MAX_VALUE, "Session sequence exhausted")
	seq++
	
	// Build IV: iv_base + seq (as signed 32-bit big-endian)
	byte[] seqBytes = new byte[4]
	int seqValue = seq
	if (seqValue < 0) {
		seqValue += 0x100000000
	}
	seqBytes[0] = (byte)((seqValue >> 24) & 0xFF)
	seqBytes[1] = (byte)((seqValue >> 16) & 0xFF)
	seqBytes[2] = (byte)((seqValue >> 8) & 0xFF)
	seqBytes[3] = (byte)(seqValue & 0xFF)
	
	byte[] iv = new byte[16]
	for (int i = 0; i < 12; i++) {
		iv[i] = aesIvBase[i]
	}
	for (int i = 0; i < 4; i++) {
		iv[i + 12] = seqBytes[i]
	}
	
	// Encrypt with PKCS5 padding
	SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES")
	IvParameterSpec ivSpec = new IvParameterSpec(iv)
	Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
	cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
	byte[] ciphertext = cipher.doFinal(plaintext)
	
	// Create signature: SHA256(signature + seq_bytes + ciphertext)
	MessageDigest sha256 = MessageDigest.getInstance("SHA-256")
	sha256.update(signature)
	sha256.update(seqBytes)
	sha256.update(ciphertext)
	byte[] sig = sha256.digest()
	
	// Return: signature (32 bytes) + ciphertext
	byte[] result = new byte[32 + ciphertext.length]
	for (int i = 0; i < 32; i++) {
		result[i] = sig[i]
	}
	for (int i = 0; i < ciphertext.length; i++) {
		result[i + 32] = ciphertext[i]
	}
	
	session.seq = seq
    state.klapSession = session // Reserve before issuing HTTP, including ambiguous failures.
	return [result, seq]
}

private byte[] klapDecrypt(byte[] ciphertext, Integer seqNum) {
	Map session = getKlapSession()
	byte[] aesKey = session.aesKey.decodeBase64()
	byte[] aesIvBase = session.aesIvBase.decodeBase64()
	int seq = seqNum != null ? seqNum : (session.seq ?: 0)
	
	if (!aesKey || !aesIvBase) {
		throw new IllegalStateException("AES key/IV not available")
	}
	
	try {
		if (ciphertext.length < 32) {
			LOG.warn "klapDecrypt: Ciphertext too short: ${ciphertext.length}"
			return null
		}
		
		byte[] seqBytes = new byte[4]
		int seqValue = seq
		if (seqValue < 0) {
			seqValue += 0x100000000
		}
		seqBytes[0] = (byte)((seqValue >> 24) & 0xFF)
		seqBytes[1] = (byte)((seqValue >> 16) & 0xFF)
		seqBytes[2] = (byte)((seqValue >> 8) & 0xFF)
		seqBytes[3] = (byte)(seqValue & 0xFF)
		
		byte[] iv = new byte[16]
		for (int i = 0; i < 12; i++) {
			iv[i] = aesIvBase[i]
		}
		for (int i = 0; i < 4; i++) {
			iv[i + 12] = seqBytes[i]
		}
		
		// Decrypt (skip signature, decrypt ciphertext)
		byte[] actualCiphertext = new byte[ciphertext.length - 32]
		for (int i = 0; i < actualCiphertext.length; i++) {
			actualCiphertext[i] = ciphertext[i + 32]
		}
		SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES")
		IvParameterSpec ivSpec = new IvParameterSpec(iv)
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
		byte[] decrypted = cipher.doFinal(actualCiphertext)
		return decrypted
		
	} catch (Exception e) {
		LOG.warn "klapDecrypt: invalid encrypted response"
		return null
	}
}

// Callback-driven, single-flight transport. Only JSON-safe values live in state.
private void klapCheck(boolean ok, String message) {
    if (!ok) throw new IllegalArgumentException("KLAP: " + message)
}
private byte[] klapBytes(Object value) {
    // Hubitat AsyncResponse returns octet-stream bodies as Base64 strings.
    klapCheck(value instanceof String && value.length() <= 131072, "Invalid binary response")
    byte[] decoded = value.decodeBase64()
    klapCheck(decoded.encodeBase64().toString() == value, "Invalid Base64 response")
    return decoded
}
private void sendKlapRequest(String method, Map params) {
    if (state.klapAuthBlocked || now() < ((state.klapRetryAfter ?: 0) as Long)) {
        if (method != "get_device_info") LOG.warn "KLAP command rejected during authentication block/cooldown"
        return
    }
    List queue = state.klapQueue ?: []
    if (method == "get_device_info" && (queue.any { it.method == method } || state.klapActive?.command?.method == method)) return
    if (queue.size() >= 16) { LOG.warn "KLAP queue full; command rejected"; return }
    queue << [method: method, params: params]
    state.klapQueue = queue
    drainKlapQueue()
}
def drainKlapQueue() {
    if (state.klapActive || !state.klapQueue) return
    try {
        String host = validateKlapHost(getDeviceAddr())
        List queue = state.klapQueue
        Map command = queue.remove(0)
        state.klapQueue = queue
        long serial = ((state.klapSerial ?: 0) as Long) + 1L
        state.klapSerial = serial
        state.klapActive = [id: serial, host: host, command: command]
        Map session = getKlapSession()
        if (session.format == 2 && session.host == host && session.aesKey instanceof String &&
            session.aesIvBase instanceof String && session.signature instanceof String &&
            session.cookie && session.expires && (session.expires as Long) > now() &&
            session.seq != null && (session.seq as Long) < Integer.MAX_VALUE) {
            sendKlapEncrypted(command)
        } else {
            state.klapSession = null
            Map credentials = getKlapCredentials()
            klapCheck(credentials != null, "Set the TP-Link username and password")
            byte[] seed = new byte[16]
            new SecureRandom().nextBytes(seed)
            state.klapHandshake = [localSeed: seed.encodeBase64().toString()]
            issueKlap("handshake1", seed)
        }
    } catch (Exception e) { klapFailSafe(e) }
}
private void issueKlap(String stage, byte[] body) {
    Map active = state.klapActive
    active.stage = stage
    state.klapActive = active
    Map token = [id: active.id, stage: stage]
    String path = stage in ["handshake1", "handshake2"] ? stage : "request?seq=" + active.seq
    String cookie = stage == "handshake2" ? state.klapHandshake?.cookie : state.klapSession?.cookie
    Map headers = cookie ? [Cookie: cookie] : [:]
    runIn(15, "klapRequestTimedOut", [data: token])
    LOG.debug "KLAP stage: " + stage
    asynchttpPost("klapResponse", [uri: "http://" + active.host + "/app/" + path,
        timeout: 5, requestContentType: "application/octet-stream", contentType: "application/octet-stream",
        headers: headers, body: body], token)
}
private boolean currentKlapRequest(Map token) {
    return state.klapActive && token && state.klapActive.id == token.id && state.klapActive.stage == token.stage
}
def klapRequestTimedOut(Map token) {
    if (currentKlapRequest(token)) klapFail("Request timed out; queued commands discarded")
}
def klapResponse(resp, Map token) {
    if (!currentKlapRequest(token)) return
    unschedule("klapRequestTimedOut")
    try {
        int status = resp.getStatus()
        // A refused handshake needs investigation, not an endless authentication loop.
        if (status == 403 && token.stage in ["handshake1", "handshake2"]) state.klapAuthBlocked = true
        klapCheck(!resp.hasError() && status == 200, "HTTP " + status + " during " + token.stage)
        if (token.stage == "handshake1") {
            byte[] data = klapBytes(resp.getData())
            klapCheck(data.length == 48, "Invalid handshake response length")
            byte[] remoteSeed = new byte[16], serverHash = new byte[32]
            for (int i = 0; i < 16; i++) remoteSeed[i] = data[i]
            for (int i = 0; i < 32; i++) serverHash[i] = data[i + 16]
            Map handshake = state.klapHandshake
            byte[] localSeed = handshake.localSeed.decodeBase64()
            Map credentials = getKlapCredentials()
            klapCheck(credentials != null, "Set the TP-Link username and password")
            List match = klapFindMatchingAuthHash(localSeed, remoteSeed, serverHash, credentials.username, credentials.password)
            if (!match) state.klapAuthBlocked = true
            klapCheck(match != null, "Authentication challenge mismatch; check compatibility/credentials, then Reset Session")
            String cookie = extractKlapCookie(resp.getHeaders())
            klapCheck(cookie && !cookie.contains("\r") && !cookie.contains("\n"), "Missing or invalid session cookie")
            klapDeriveSessionKeys(localSeed, remoteSeed, match[0])
            handshake.cookie = cookie
            state.klapHandshake = handshake
            issueKlap("handshake2", klapHandshake2Hash(localSeed, remoteSeed, match[0], match[1]))
        } else if (token.stage == "handshake2") {
            Map session = getKlapSession()
            session.cookie = state.klapHandshake.cookie
            session.host = state.klapActive.host
            session.expires = now() + 600000L
            session.terminalUuid = getTerminalUuid()
            state.klapSession = session
            state.klapHandshake = null
            sendKlapEncrypted(state.klapActive.command)
        } else {
            byte[] plain = klapDecrypt(klapBytes(resp.getData()), state.klapActive.seq as Integer)
            klapCheck(plain != null, "Invalid encrypted response")
            Map reply = new JsonSlurper().parseText(new String(plain, "UTF-8")) as Map
            klapCheck(reply.error_code instanceof Number && reply.error_code == 0,
                "Device command error " + (reply.error_code instanceof Number ? reply.error_code : "(missing)"))
            if (token.stage == "request" && state.klapActive.command.method == "set_device_info") {
                sendKlapEncrypted([method: "get_device_info", params: [:]], "verify")
            } else {
                klapCheck(reply.result instanceof Map, "Device info missing")
                updateSwitchState(reply.result)
                if (state.klapActive.command.method == "set_device_info") {
                    klapCheck(state.klapActive.command.params.every { k, v -> reply.result[k] == v },
                        "Command acknowledged but read-back did not match")
                }
                setCommsError(false)
                sendEvent(name: "lastError", value: "none")
                state.klapActive = null
                runInMillis(50, "drainKlapQueue")
            }
        }
    } catch (Exception e) { klapFailSafe(e) }
}
private void sendKlapEncrypted(Map command, String stage = "request") {
    Map session = getKlapSession()
    Map payload = command + [requestTimeMils: now(), terminalUUID: session.terminalUuid]
    List encrypted = klapEncrypt(JsonOutput.toJson(payload).getBytes("UTF-8"))
    Map active = state.klapActive
    active.seq = encrypted[1]
    state.klapActive = active
    issueKlap(stage, encrypted[0])
}
private void klapFailSafe(Exception e) {
    // Exception messages can contain HTTP cookies/URLs. Log only our safe errors.
    String reason = e instanceof IllegalArgumentException && e.message?.startsWith("KLAP: ") ?
        e.message.substring(6) : e.class.simpleName + " during " + (state.klapActive?.stage ?: "setup")
    klapFail(reason)
}
private void klapFail(String reason) {
    state.klapActive = null
    state.klapQueue = []
    state.klapHandshake = null
    state.klapSession = null
    state.klapRetryAfter = now() + 300000L
    unschedule("klapRequestTimedOut")
    setCommsError(true)
    sendEvent(name: "lastError", value: reason)
    LOG.warn "KLAP: " + reason + (state.klapAuthBlocked ? "; use Reset Session after investigation" : "; no command replay")
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
