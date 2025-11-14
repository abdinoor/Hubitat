import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import groovy.transform.Field
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Random
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

metadata {
	definition (name: "Tapo KLAP LAN Device",
				namespace: "klap",
				author: "Dan Abdinoor",
				importUrl: 'https://raw.githubusercontent.com/abdinoor/Hubitat/refs/heads/master/klap-lan-driver.groovy'
			   ) {
        capability "Switch"
        capability "SwitchLevel"
        capability "Refresh"
		attribute "connection", "string"
		attribute "commsError", "string"
		attribute "deviceIP", "string"
		attribute "deviceStatus", "string"
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

@Field static final String VERSION = "1.0.0"

def installed() {
	pauseExecution(3000)
	def instStatus = [:]
	sendEvent(name: "connection", value: "LAN")
	sendEvent(name: "commsError", value: "false")
	state.errorCount = 0
	runIn(1, updated)
	LOG.info "installed: ${instStatus}"
}

def updated() {
	unschedule()
	removeDataValue("driverVersion")
	refresh()

	def updStatus = [:]
	updStatus << [txtEnable: txtEnable, logEnable: logEnable]

	if (manualIp != getDataValue("deviceIP")) {
		updateDataValue("deviceIP", manualIp)
		sendEvent(name: "deviceIP", value: manualIp)
		updStatus << [ipUpdate: manualIp]
	}

	state.model = getDataValue("model")

	state.errorCount = 0
	sendEvent(name: "commsError", value: "false")

    updateDataValue("pollRefresh", pollRefresh.toString())
    updStatus << [pollRefresh: pollRefresh]

    runIn(getRefreshSeconds(), poll)
	runIn(5, listAttributes)

	LOG.info "updated: ${updStatus}"
}

def refresh() {
	// Fetch device info using KLAP
	Map result = sendKlapRequest("get_device_info", [:])
	if (result && result.error_code == 0) {
		def status = result.result ?: [:]
		setDeviceStatus(status)
		setCommsError(false)
	} else {
		LOG.warn "refresh: Failed to fetch device info${result?.error_code ? " (error_code=${result.error_code})" : ""}"
		setCommsError(true)
	}
}

def poll() {
	refresh()
	runIn(getRefreshSeconds(), poll)
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
    return Integer.parseInt(getDataValue("pollRefresh"))
}

def getDeviceAddr() {
	return getDataValue("deviceIP")
}

def setDeviceStatus(status) {
	LOG.debug "setDeviceStatus status: ${status}"
	def logData = [:]
	
	if (status.device_on != null) {
		String switchVal = status.device_on ? "on" : "off"
		if (switchVal != device.currentValue("switch")) {
			sendEvent(name: "switch", value: switchVal, descriptionText: "${device.displayName} switch is ${switchVal}")
			logData << [switch: switchVal]
		}
	}
	if (status.brightness != null) {
		Integer levelValue = status.brightness as Integer
		if (levelValue != device.currentValue("level")) {
			sendEvent(name: "level", value: levelValue, descriptionText: "${device.displayName} level is ${levelValue}")
			logData << [level: levelValue]
		}
	}
	
	// Convert status to JSON string for display
	String statusJson = JsonOutput.toJson(status)
	if (statusJson != device.currentValue("deviceStatus")) {
		sendEvent(name: "deviceStatus", value: statusJson, descriptionText: "Device status updated")
		logData << [deviceStatus: "updated"]
	}

	if (logData.size() > 0) {
		LOG.desc "status changed: ${logData}"
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

def on() {
	sendDevicePowerCommand(true)
}

def off() {
	sendDevicePowerCommand(false)
}

private void sendDevicePowerCommand(boolean turnOn) {
	Map response = sendKlapRequest("set_device_info", [device_on: turnOn])
	if (response && response.error_code == 0) {
		String switchVal = turnOn ? "on" : "off"
		sendEvent(name: "switch", value: switchVal, descriptionText: "${device.displayName} switch is ${switchVal}")
		setCommsError(false)
		runIn(1, "refresh")
	} else {
		LOG.warn "sendDevicePowerCommand: command failed${response?.error_code ? " (error_code=${response.error_code})" : ""}"
		setCommsError(true)
	}
}

def setLevel(level, duration = null) {
	Integer levelInt = level as Integer
	if (levelInt < 0) levelInt = 0
	if (levelInt > 100) levelInt = 100
	Map params = [
		device_on: (levelInt > 0),
		brightness: levelInt
	]
	Map response = sendKlapRequest("set_device_info", params)
	if (response && response.error_code == 0) {
		sendEvent(name: "switch", value: levelInt > 0 ? "on" : "off", descriptionText: "${device.displayName} switch is ${levelInt > 0 ? 'on' : 'off'}")
		sendEvent(name: "level", value: levelInt, descriptionText: "${device.displayName} level is ${levelInt}")
		setCommsError(false)
		runIn(1, "refresh")
	} else {
		LOG.warn "setLevel: command failed${response?.error_code ? " (error_code=${response.error_code})" : ""}"
		setCommsError(true)
	}
}

// ============================================================================
// KLAP Protocol Implementation
// ============================================================================

private Map getKlapCredentials() {
	String username = settings?.klapUsername?.trim()
	String password = settings?.klapPassword?.trim()
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
	def rng = new Random()
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
		LOG.warn "extractKlapCookie: error accessing headers: ${e.message}"
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
		seqBytes[i] = fullIv[i + 12]
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
	
	session.aesKey = aesKey
	session.aesIvBase = aesIvBase
	session.signature = signature
	session.seq = seq
}

private boolean klapHandshake() {
	LOG.debug "klapHandshake: starting KLAP handshake"
	Map creds = getKlapCredentials()
	if (!creds) {
		LOG.warn "klapHandshake: credentials not available"
		return false
	}
	
	String host = getDeviceAddr()
	String baseUrl = "http://${host}/app"
	
	// Generate local seed (16 random bytes)
	Random random = new Random()
	byte[] localSeed = new byte[16]
	random.nextBytes(localSeed)
	
	// Stage 1: Send local seed as RAW BYTES via asynchttpPost (Hubitat-safe)
	try {
		String handshake1Url = "${baseUrl}/handshake1"
		def syncResult = [waiting: true, completed: false]
		
		Map params = [
			uri: handshake1Url,
			requestContentType: 'application/octet-stream',
			contentType: 'application/octet-stream',
			timeout: 5,
			body: localSeed
		]
		
		asynchttpPost('klapHandshake1Callback', params, [result: syncResult])
		
		int waitCount = 0
		while (syncResult.waiting && waitCount < 50) {
			pauseExecution(100)
			waitCount++
		}
		
		if (syncResult.waiting) {
			LOG.warn "klapHandshake: Stage 1 timeout waiting for response"
			return false
		}
		
		if (!syncResult.completed) {
			LOG.warn "klapHandshake: Stage 1 request failed"
			return false
		}
		
		if (syncResult.status != 200) {
			LOG.warn "klapHandshake: Stage 1 HTTP error: ${syncResult.status}"
			return false
		}
		
		byte[] responseBytes = decodeIfBase64(syncResult.data)
		if (!responseBytes) {
			LOG.warn "klapHandshake: Stage 1 response data is null"
			return false
		}
		
		LOG.debug "klapHandshake: Stage 1 response length: ${responseBytes.length} bytes"
		
		if (responseBytes.length < 48) {
			LOG.warn "klapHandshake: Stage 1 invalid response length: ${responseBytes.length} (expected at least 48)"
			return false
		}
		
		LOG.debug "klapHandshake: Stage 1 response length: ${responseBytes.length} bytes (using first 48)"
		
		// Extract remote seed and server hash (first 16 bytes = remote_seed, next 32 bytes = server_hash)
		byte[] remoteSeed = new byte[16]
		byte[] serverHash = new byte[32]
		for (int i = 0; i < 16; i++) {
			remoteSeed[i] = responseBytes[i]
		}
		for (int i = 0; i < 32; i++) {
			serverHash[i] = responseBytes[i + 16]
		}
		
		// Debug: log the extracted values (matching tapo-lan-driver.groovy)
		String remoteSeedHex = remoteSeed.encodeHex().toString()
		String serverHashHex = serverHash.encodeHex().toString()
		LOG.debug "klapHandshake: Extracted remoteSeed (hex): ${remoteSeedHex}"
		LOG.debug "klapHandshake: Extracted serverHash (hex): ${serverHashHex}"
		
		// Extract cookie (TP_SESSIONID)
		String cookie = extractKlapCookie(syncResult.headers)
		if (!cookie) {
			LOG.warn "klapHandshake: Warning: No cookie found"
		} else {
			// Ensure cookie is just the value, not "Cookie: value" - match test implementation
			if (cookie.startsWith("Cookie:")) {
				cookie = cookie.substring(7).trim()
			}
			// Trim any whitespace
			cookie = cookie.trim()
			LOG.debug "klapHandshake: Cookie extracted (length=${cookie.length()}): ${cookie.length() > 30 ? cookie.substring(0, 30) + '...' : cookie}"
		}
		
		// Try to find matching auth_hash
		def authResult = klapFindMatchingAuthHash(localSeed, remoteSeed, serverHash, creds.username, creds.password)
		
		byte[] authHash
		boolean useV2
		if (authResult) {
			authHash = authResult[0]
			useV2 = authResult[1]
			String hashHex = authHash.encodeHex().toString()
			LOG.debug "klapHandshake: Using auth hash (${useV2 ? 'V2' : 'V1'}): ${hashHex.length() > 16 ? hashHex.substring(0, 16) + '...' : hashHex}"
		} else {
			// If no match found, try with user credentials V2 first, then V1 as fallback
			LOG.warn "klapHandshake: No exact hash match, trying with user credentials V2 first..."
			byte[] authHashV2 = klapComputeAuthHash(creds.username, creds.password, true)
			byte[] expectedHashV2 = klapHandshake1Hash(localSeed, remoteSeed, authHashV2, true)
			boolean v2Matches = (serverHash.length == expectedHashV2.length)
			if (v2Matches) {
				for (int i = 0; i < serverHash.length; i++) {
					if (serverHash[i] != expectedHashV2[i]) {
						v2Matches = false
						break
					}
				}
			}
			
			if (v2Matches) {
				LOG.debug "klapHandshake: V2 hash matches, using V2"
				authHash = authHashV2
				useV2 = true
			} else {
				LOG.warn "klapHandshake: V2 doesn't match, trying V1..."
				authHash = klapComputeAuthHash(creds.username, creds.password, false)
				useV2 = false
			}
		}
		
		// Stage 2: Send hash as RAW BYTES - match test implementation
		LOG.debug "klapHandshake: Stage 2: Sending hash as raw bytes..."
		return klapHandshake2(localSeed, remoteSeed, authHash, useV2, cookie, baseUrl)
		
	} catch (Exception e) {
		LOG.warn "klapHandshake: Handshake exception: ${e.message}"
		return false
	}
}

private boolean klapHandshake2(byte[] localSeed, byte[] remoteSeed, byte[] authHash, boolean useV2, String cookie, String baseUrl) {
	try {
		// Compute hash based on protocol version
		byte[] clientHash = klapHandshake2Hash(localSeed, remoteSeed, authHash, useV2)
		String clientHashHex = clientHash.encodeHex().toString()
		LOG.debug "klapHandshake2: Client hash computed (${useV2 ? 'V2' : 'V1'}), length=${clientHash.length}, hash=${clientHashHex}"
		
		// Use asynchttpPost for Stage 2 as well
		String handshake2Url = "${baseUrl}/handshake2"
		def syncResult2 = [waiting: true, completed: false]
		
		Map headers2 = [:]
		if (cookie) {
			String trimmedCookie = cookie.trim()
			headers2.Cookie = trimmedCookie
			LOG.debug "klapHandshake2: Sending cookie (length=${trimmedCookie.length()}): ${trimmedCookie.length() > 30 ? trimmedCookie.substring(0, 30) + '...' : trimmedCookie}"
			LOG.debug "klapHandshake2: Client hash length: ${clientHash.length} bytes"
		} else {
			LOG.warn "klapHandshake2: No cookie available for Stage 2"
		}
		
		Map params2 = [
			uri: handshake2Url,
			requestContentType: 'application/octet-stream',
			contentType: 'application/octet-stream',
			timeout: 5,
			body: clientHash
		]
		params2.headers = headers2
		
		asynchttpPost('klapHandshake2Callback', params2, [result: syncResult2])
		
		int waitCount2 = 0
		while (syncResult2.waiting && waitCount2 < 50) {
			pauseExecution(100)
			waitCount2++
		}
		
		if (syncResult2.waiting) {
			LOG.warn "klapHandshake2: Stage 2 timeout waiting for response"
			return false
		}
		
		if (syncResult2.status != 200) {
			LOG.warn "klapHandshake2: Stage 2 HTTP error: ${syncResult2.status}"
			return false
		}
		
		// Derive final AES key and IV from seeds
		klapDeriveSessionKeys(localSeed, remoteSeed, authHash)
		Map session = getKlapSession()
		session.cookie = cookie
		session.terminalUuid = getTerminalUuid()
		session.useV2 = useV2
		
		LOG.debug "klapHandshake2: Handshake successful!"
		return true
		
	} catch (Exception e) {
		LOG.warn "klapHandshake2: Stage 2 exception: ${e.message}"
		return false
	}
}

private List klapEncrypt(byte[] plaintext) {
	Map session = getKlapSession()
	byte[] aesKey = session.aesKey
	byte[] aesIvBase = session.aesIvBase
	byte[] signature = session.signature
	int seq = session.seq ?: 0
	
	if (!aesKey || !aesIvBase || !signature) {
		throw new IllegalStateException("AES key/IV not available")
	}
	
	// Increment sequence number
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
	return [result, seq]
}

private byte[] klapDecrypt(byte[] ciphertext, Integer seqNum) {
	Map session = getKlapSession()
	byte[] aesKey = session.aesKey
	byte[] aesIvBase = session.aesIvBase
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
		LOG.warn "klapDecrypt: Decryption error: ${e.message}"
		return null
	}
}

// Async HTTP callbacks no longer required (synchronous HTTP now used)

private boolean ensureKlapSession() {
	Map session = getKlapSession()
	if (session.aesKey && session.cookie && session.seq != null) {
		LOG.debug "ensureKlapSession: existing KLAP session still valid"
		return true
	}
	
	LOG.debug "ensureKlapSession: establishing new KLAP session"
	if (klapHandshake()) {
		setCommsError(false)
		return true
	} else {
		setCommsError(true)
		return false
	}
}

private Map sendKlapRequest(String method, Map params) {
	if (!ensureKlapSession()) {
		LOG.warn "sendKlapRequest: KLAP session unavailable"
		return null
	}
	
	Map session = getKlapSession()
	
	// Create request payload (as JSON string)
	Map payload = [
		method: method,
		requestTimeMils: now(),
		terminalUUID: session.terminalUuid ?: getTerminalUuid(),
		params: params
	]
	
	// Encrypt payload
	String payloadJson = JsonOutput.toJson(payload)
	def encryptedResult = klapEncrypt(payloadJson.getBytes("UTF-8"))
	byte[] encryptedData = encryptedResult[0]
	int requestSeq = encryptedResult[1]
	
	try {
		String cookieValue = session.cookie
		if (cookieValue && cookieValue.contains(":")) {
			cookieValue = cookieValue.split(":", 2)[1].trim()
		}
		
		String requestUrl = "http://${getDeviceAddr()}/app/request?seq=${requestSeq}"
		def syncResult = [waiting: true, completed: false]
		
		Map headers = [:]
		if (cookieValue) {
			headers.Cookie = cookieValue
		}
		headers['Content-Type'] = 'application/octet-stream'
		
		Map httpParams = [
			uri: requestUrl,
			requestContentType: 'application/octet-stream',
			contentType: 'application/octet-stream',
			timeout: 5,
			body: encryptedData,
			headers: headers
		]
		
		asynchttpPost('klapRequestCallback', httpParams, [result: syncResult, seq: requestSeq])
		
		int waitCount = 0
		while (syncResult.waiting && waitCount < 50) {
			pauseExecution(100)
			waitCount++
		}
		
		if (syncResult.waiting) {
			LOG.warn "sendKlapRequest: timeout waiting for response"
			return null
		}
		
		if (!syncResult.completed) {
			LOG.warn "sendKlapRequest: request failed with status ${syncResult.status}"
			return null
		}
		
		byte[] encryptedResponse = decodeIfBase64(syncResult.data)
		if (!encryptedResponse) {
			LOG.warn "sendKlapRequest: empty response body"
			return null
		}
		
		byte[] decryptedBytes = klapDecrypt(encryptedResponse, requestSeq)
		if (!decryptedBytes) {
			LOG.warn "sendKlapRequest: failed to decrypt response"
			return null
		}
		
		String resultJson = new String(decryptedBytes, "UTF-8")
		JsonSlurper slurper = new JsonSlurper()
		Map parsed = slurper.parseText(resultJson)
		return parsed
		
	} catch (Exception e) {
		LOG.warn "sendKlapRequest: exception during request [error: ${e.message}]"
		return null
	}
}

// ---------------------------------------------------------------------------
// Async HTTP callbacks for KLAP binary exchanges
// ---------------------------------------------------------------------------

private byte[] decodeIfBase64(byte[] bytes) {
	if (!bytes) return bytes
	if (bytes.length % 4 != 0) {
		return bytes
	}
	boolean ascii = true
	for (int i = 0; i < bytes.length; i++) {
		int c = bytes[i] & 0xFF
		if ((c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) ||
			c == 0x2B || c == 0x2F || c == 0x3D || c == 0x0A || c == 0x0D) {
			continue
		}
		ascii = false
		break
	}
	if (!ascii) {
		return bytes
	}
	try {
		String asciiStr = new String(bytes, "UTF-8").replace("\n", "").replace("\r", "")
		byte[] decoded = asciiStr.decodeBase64()
		if (decoded && decoded.length > 0) {
			LOG.debug "decodeIfBase64: decoded base64 payload length=${decoded.length}"
			return decoded
		}
	} catch (Exception ignored) { }
	return bytes
}

private byte[] responseBytes(resp) {
	def data
	try {
		data = resp?.data
	} catch (Exception ignored) { }
	if (data instanceof byte[]) {
		return data
	}
	if (data instanceof String) {
		return data.getBytes("ISO-8859-1")
	}
	try {
		data = resp?.rawBody
	} catch (Exception ignored) { }
	if (data instanceof byte[]) {
		return data
	}
	if (data instanceof String) {
		return data.getBytes("ISO-8859-1")
	}
	try {
		data = resp?.body
	} catch (Exception ignored) { }
	if (data instanceof byte[]) {
		return data
	}
	if (data instanceof String) {
		return data.getBytes("ISO-8859-1")
	}
	return null
}

def klapHandshake1Callback(resp, data) {
	try {
		Map result = data.result
		result.waiting = false
		result.status = resp.status ?: 0
		result.headers = resp.headers ?: [:]
		result.data = responseBytes(resp)
		result.completed = (result.status == 200 && result.data != null)
		if (result.status == 200 && result.data == null) {
			LOG.warn "klapHandshake1Callback: no response data available (status=${result.status})"
		}
	} catch (Exception e) {
		LOG.warn "klapHandshake1Callback: error processing response: ${e.message}"
		if (data?.result) {
			data.result.waiting = false
			data.result.completed = false
			data.result.status = 0
			data.result.headers = [:]
			data.result.data = null
		}
	}
}

def klapHandshake2Callback(resp, data) {
	try {
		Map result = data.result
		result.waiting = false
		result.status = resp.status ?: 0
		result.completed = (result.status == 200)
	} catch (Exception e) {
		LOG.warn "klapHandshake2Callback: error processing response: ${e.message}"
		if (data?.result) {
			data.result.waiting = false
			data.result.completed = false
			data.result.status = 0
		}
	}
}

def klapRequestCallback(resp, data) {
	try {
		Map result = data.result
		result.waiting = false
		result.status = resp.status ?: 0
		result.headers = resp.headers ?: [:]
		result.data = responseBytes(resp)
		result.completed = (result.status == 200 && result.data != null)
		if (result.status == 200 && result.data == null) {
			LOG.warn "klapRequestCallback: no response data available"
		}
	} catch (Exception e) {
		LOG.warn "klapRequestCallback: error processing response: ${e.message}"
		if (data?.result) {
			data.result.waiting = false
			data.result.completed = false
			data.result.status = 0
			data.result.data = null
		}
	}
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

