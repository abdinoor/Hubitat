import groovy.json.JsonSlurper
import groovy.transform.Field
import org.json.JSONObject

metadata {
	definition (name: "Kasa LAN Device",
				namespace: "kasa",
				author: "Dan Abdinoor",
				importUrl: 'https://raw.githubusercontent.com/abdinoor/Hubitat/refs/heads/master/kasa-lan-driver.groovy'
			   ) {
        capability "Switch"
        capability "Refresh"
        capability "Switch Level"
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
		input ("rebootDev", "bool",
			   title: "Reboot device <b>[Caution]</b>",
			   defaultValue: false)
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
	state.remove("response")
	state.remove("pollInterval")
	state.remove("lastCommand")
	state.remove("plugId")
	removeDataValue("driverVersion")
	removeDataValue("plugId")
	refresh()


	def updStatus = [:]
	if (rebootDev) {
		updStatus << [rebootDev: reboot()]
		return updStatus
	}

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
	sendCmd("""{"system":{"get_sysinfo":{}}}""")
}

def poll() {
	refresh()
	runIn(getRefreshSeconds(), poll)
}

def reboot() {
	sendCmd("""{"${sysService()}":{"reboot":{"delay":1}}}""")
}


/**
SWITCH METHODS
*/

def on() {
	setRelayState(1)
	sendEvent(name: "switch", value: "on")
}

def off() {
	setRelayState(0)
	sendEvent(name: "switch", value: "off")
}

def setRelayState(onOff) {
	if (getDataValue("plugNo")?.trim()) {
		def plugNo = getDataValue("plugNo")
		sendCmd("""{"context":{"child_ids":["${getDataValue("plugNo")}"]},""" +
				""""system":{"set_relay_state":{"state":${onOff}}}}""")
	} else {
		sendCmd("""{"system":{"set_relay_state":{"state":${onOff}}}}""")
	}

	LOG.desc "setRelayState: [switch: ${onOff}]"
}


/**
DIMMER METHODS
*/

def setLevel(level, transTime = 100) {
    level = checkLevel(level)
    LOG.desc "setLevel: [level: ${level}, transTime: ${transTime}]"
    if (level == 0) {
        setRelayState(0)
    } else {
        sendCmd("""{"smartlife.iot.dimmer":{"set_dimmer_transition":{"brightness":${level},"duration":${transTime}}}}""")
    }
    sendEvent(name: "switch", value: "on", type: "digital")
    sendEvent(name: "level", value: level, type: "digital")

    def updates = ['switch': "on", level: level]
    LOG.desc "setLevel: ${updates}"
}

def presetLevel(level) {
    presetBrightness(level)
}

def checkLevel(level) {
    if (level == null || level < 0) {
        level = device.currentValue("level")
        LOG.warn "checkLevel: Entered level null or negative. Level set to ${level}"
    } else if (level > 100) {
        level = 100
        LOG.warn "checkLevel: Entered level > 100.  Level set to ${level}"
    }
    return level
}

def presetBrightness(level) {
    level = checkLevel(level)
    LOG.desc "presetLevel: [level: ${level}]"
    sendCmd("""{"smartlife.iot.dimmer":{"set_brightness":{"brightness":${level}}},"system" :{"get_sysinfo" :{}}}""")
}


/**
HELPER METHODS
*/

def sysService() {
	def service = "system"
	def feature = getDataValue("feature")
	if (feature.contains("Bulb") || feature == "lightStrip") {
		service = "smartlife.iot.common.system"
	}
	return service
}

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

def getPort() {
	def port = 9999
	if (getDataValue("devicePort")) {
		port = getDataValue("devicePort")
	}
	return port
}

def getDeviceAddr() {
	return getDataValue("deviceIP")
}


/**
COMMS METHODS
*/

def sendCmd(command) {
	state.lastCommand = command
	sendLanCmd(command)
}

def sendLanCmd(command) {
	LOG.debug "sendLanCmd: [IP: ${getDeviceAddr()}, cmd: ${command}]"
	def myHubAction = new hubitat.device.HubAction(
		outputXOR(command),
		hubitat.device.Protocol.LAN,
		[type: hubitat.device.HubAction.Type.LAN_TYPE_UDPCLIENT,
		 destinationAddress: "${getDeviceAddr()}:${getPort()}",
		 encoding: hubitat.device.HubAction.Encoding.HEX_STRING,
		 parseWarning: true,
		 timeout: 9,
		 ignoreResponse: false,
		 callback: "parseUdp"])
	try {
		sendHubCommand(myHubAction)
	} catch (e) {
		handleCommsError()
		LOG.warn "sendLanCmd: LAN Error = ${e}.\n\rNo retry on this error."
	}
}

def close() {
	interfaces.rawSocket.close()
}

def socketStatus(message) {
	if (message != "receive error: Stream closed.") {
		LOG.debug "socketStatus: Socket Established"
	} else {
		LOG.warn "socketStatus = ${message}"
	}
}

def handleCommsError() {
	Map logData = [:]
	def lastCmd = state.lastCommand
	if (lastCmd?.trim()) {
		def count = state.errorCount + 1
		state.errorCount = count
		def retry = true
		logData << [count: count, command: lastCmd]
		switch (count) {
			case 1:
			case 2:
				sendCmd(lastCmd)
				LOG.debug "handleCommsError: ${logData}"
				break
			case 3:
				logData << [setCommsError: setCommsError(true), status: "retriesDisabled"]
				LOG.error "handleCommsError: ${logData}"
				break
			default:
				break
		}
	}
}


/**
RESPONSE HANDLING METHODS
*/

def parse(message) {
	if (message == null) {
		return
	}

	def response = state.response.concat(message)
	state.response = response
	def clearResp = inputXorTcp(response)
	if (clearResp.endsWith("}}}")) {
		interfaces.rawSocket.close()
		try {
			distResp(parseJson(clearResp))
			setCommsError(false)
		} catch (e) {
			LOG.warn "extractTcpResp: [length: ${clearResp.length()}, clearResp: ${clearResp}, comms error: ${e}]"
		}
	} else if (clearResp.length() > 2000) {
		interfaces.rawSocket.close()
	}
}

def parseUdp(message) {
	def resp = parseLanMessage(message)
	if (resp.type != "LAN_TYPE_UDPCLIENT") {
		LOG.debug "parseUdp: [error: error, reason: not LAN_TYPE_UDPCLIENT, respType: ${resp.type}])"
		handleCommsError()
		return
	}

	def clearResp = inputXOR(resp.payload)
	if (clearResp.length() > 1023) {
		if (clearResp.contains("preferred")) {
			clearResp = clearResp.substring(0,clearResp.indexOf("preferred")-2) + "}}}"
		} else if (clearResp.contains("child_num")) {
			clearResp = clearResp.substring(0,clearResp.indexOf("child_num") -2) + "}}}"
		} else {
			LOG.warn "parseUdp: udp msg can not be parsed]"
			LOG.debug "parseUdp: [messageData: ${clearResp}]"
			return
		}
	}
	try {
		def cmdResp = new JsonSlurper().parseText(clearResp)
		LOG.debug "parseUdp: ${cmdResp}"
		distResp(cmdResp)
		setCommsError(false)
	} catch (e) {
		LOG.warn "parseUdp: JSON parse failed [reason: ${e?.message}]"
		LOG.debug "parseUdp: [messageData: ${clearResp}]"
		return
	}
}

def distResp(response) {
	if (!response.system) {
		LOG.debug "distResp: Unhandled response = ${response}"
		return
	}

	if (response.system.get_sysinfo) {
		setSysInfo(response.system.get_sysinfo)
	} else if (response.system.set_relay_state) {
		refresh()
	} else if (response.system.reboot) {
		LOG.warn "distResp: Rebooting device."
	} else if (response.system.set_dev_alias) {
		updateName(response.system.set_dev_alias)
	} else {
		LOG.debug "distResp: Unhandled response = ${response}"
	}
}

def setSysInfo(status) {
	LOG.debug "setSysInfo status: ${status}"
	def logData = [:]
	def switchStatus = status.relay_state

	// for smart plugs get the child device with this plugNo
	if (getDataValue("plugNo")?.trim()) {
		def childStatus = status.children.find { it.id == getDataValue("plugNo") }
		switchStatus = childStatus?.state
	}

	def onOff = switchStatus == 1 ? "on" : "off"
	if (onOff != device.currentValue("switch")) {
		sendEvent(name: "switch", value: onOff, descriptionText: "Switch is ${onOff}")
		logData << [switch: onOff]
	}

	def level = status.brightness
	if (level != null && level != device.currentValue("level")) {
		sendEvent(name: "level", value: level, descriptionText: "Dimmer level is ${level}")
		logData << [level: level]
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
		sendEvent(name: "commsError", value: "false")
		return "commsErrorSet"
	}
}

private outputXOR(command) {
	def str = ""
	def encrCmd = ""
 	def key = 0xAB
	for (int i = 0; i < command.length(); i++) {
		str = (command.charAt(i) as byte) ^ key
		key = str
		encrCmd += Integer.toHexString(str)
	}
   	return encrCmd
}

private inputXOR(encrResponse) {
	String[] strBytes = encrResponse.split("(?<=\\G.{2})")
	def cmdResponse = ""
	def key = 0xAB
	def nextKey
	byte[] XORtemp
	for(int i = 0; i < strBytes.length; i++) {
		nextKey = (byte)Integer.parseInt(strBytes[i], 16)	// could be negative
		XORtemp = nextKey ^ key
		key = nextKey
		cmdResponse += new String(XORtemp)
	}
	return cmdResponse
}

private inputXorTcp(resp) {
	String[] strBytes = resp.substring(8).split("(?<=\\G.{2})")
	def cmdResponse = ""
	def key = 0xAB
	def nextKey
	byte[] XORtemp
	for(int i = 0; i < strBytes.length; i++) {
		nextKey = (byte)Integer.parseInt(strBytes[i], 16)	// could be negative
		XORtemp = nextKey ^ key
		key = nextKey
		cmdResponse += new String(XORtemp)
	}
	return cmdResponse
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
