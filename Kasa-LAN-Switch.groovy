def driverVer() { return "2.4.0" }

def type() { return "Kasa LAN Switch" }

def file() { return type().replaceAll(" ", "-") }

metadata {
	definition (name: "Kasa LAN Switch",
				namespace: "kasa",
				author: "Dave Gutheinz",
			   ) {
		capability "Switch"
		capability "Actuator"
		capability "Configuration"
		capability "Refresh"
		command "setPollInterval", [[
			name: "Poll Interval in seconds",
			constraints: ["default", "1 second", "5 seconds", "10 seconds",
						  "15 seconds", "30 seconds", "1 minute", "5 minutes",
						  "10 minutes", "30 minutes"],
			type: "ENUM"]]
		attribute "connection", "string"
		attribute "commsError", "string"
		attribute "deviceIP", "string"
}
//	6.7.2 Change B.  change logging names and titles to match other built-in drivers.
	preferences {
		input ("textEnable", "bool",
			   title: "Enable descriptionText logging",
			   defaultValue: true)
		input ("logEnable", "bool",
			   title: "Enable debug logging",
			   defaultValue: false)
		input ("bind", "bool",
			   title: "Kasa Cloud Binding",
			   defalutValue: true)
		input ("nameSync", "enum", title: "Synchronize Names",
			   options: ["none": "Don't synchronize",
						 "device" : "Kasa device name master",
						 "Hubitat" : "Hubitat label master"],
			   defaultValue: "none")
		input ("manualIp", "string",
			   title: "Device IP Address",
			   defaultValue: getDataValue("deviceIP"))
		input ("manualPort", "string",
			   title: "Device Port",
			   defaultValue: getDataValue("devicePort"))
		input ("rebootDev", "bool",
			   title: "Reboot device <b>[Caution]</b>",
			   defaultValue: false)
	}
}

def installed() {
	device.updateSetting("nameSync",[type:"enum", value:"device"])
	def instStatus = installCommon()
	logInfo("installed: ${instStatus}")
}

def updated() {
	def updStatus = updateCommon()
	logInfo("updated: ${updStatus}")

	if (getDataValue("model") == "HS300") {
		state.remove("response")
	}

	refresh()
}

def setSysInfo(status) {
	def switchStatus = status.relay_state
	def logData = [:]
	if (getDataValue("plugNo") != null) {
		def childStatus = status.children.find { it.id == getDataValue("plugNo") }
		if (childStatus == null) {
			childStatus = status.children.find { it.id == getDataValue("plugId") }
		}
		status = childStatus
		switchStatus = status.state
	}

	def onOff = "on"
	if (switchStatus == 0) { onOff = "off" }
	if (device.currentValue("switch") != onOff) {
		sendEvent(name: "switch", value: onOff, type: "digital")
		logData << [switch: onOff]
	}

	if (logData != [:]) {
		logInfo("setSysInfo: ${logData}")
	}
	if (nameSync == "device" || nameSync == "Hubitat") {
		updateName(status)
	}
}

// ~~~~~ start kasaCommon ~~~~~
library (
	name: "kasaCommon",
	namespace: "kasa",
	author: "Dave Gutheinz",
	description: "Kds",
	category: "utilities",
	documentationLink: ""
)

def installCommon() {
	pauseExecution(3000)
	def instStatus = [:]
	sendEvent(name: "connection", value: "LAN")
	device.updateSetting("useCloud", [type:"bool", value: false])
	instStatus << [useCloud: false, connection: "LAN"]
	sendEvent(name: "commsError", value: "false")
	state.errorCount = 0
	state.pollInterval = "1 minute"
	runIn(1, updated)
	return instStatus
}

def updateCommon() {
	def updStatus = [:]
	if (rebootDev) {
		updStatus << [rebootDev: rebootDevice()]
		return updStatus
	}
	unschedule()
	updStatus << [bind: bindUnbind()]
	if (nameSync != "none") {
		updStatus << [nameSync: syncName()]
	}
	if (logEnable) {
		// turn off debug logging in 30 minutes
		runIn(1800, debugLogOff)
	}
	updStatus << [textEnable: textEnable, logEnable: logEnable]
	if (manualIp != getDataValue("deviceIP")) {
		updateDataValue("deviceIP", manualIp)
		sendEvent(name: "deviceIP", value: manualIp)
		updStatus << [ipUpdate: manualIp]
	}
	if (manualPort != getDataValue("devicePort")) {
		updateDataValue("devicePort", manualPort)
		updStatus << [portUpdate: manualPort]
	}
	state.model = getDataValue("model")
	state.errorCount = 0
	sendEvent(name: "commsError", value: "false")
	def pollInterval = state.pollInterval
	if (pollInterval == null) { pollInterval = "1 minute" }
	updStatus << [pollInterval: setPollInterval(pollInterval)]
	state.remove("UPDATE_AVAILABLE")
	state.remove("releaseNotes")
	removeDataValue("driverVersion")
	runIn(5, listAttributes)
	return updStatus
}

def configure() {
	if (parent == null) {
		logWarn("configure: No Parent Detected.  Configure function ABORTED.  Use Save Preferences instead.")
	} else {
		def confStatus = parent.updateConfigurations()
		logInfo("configure: ${confStatus}")
	}
}

def refresh() {
	getSysinfo()
}

def poll() {
	unschedule('poll')
	getSysinfo()
	def pollInterval = getPollInterval(state.pollInterval)
	runIn(pollInterval, poll)
}

def getPollInterval(descInterval) {
	def interval = descInterval.substring(0,2).toInteger()
	if (descInterval.contains("1 second")) {
		return 1
	}

	if (descInterval.contains("sec")) {
		return interval
	}

	return interval * 60
}

def setPollInterval(interval = state.pollInterval) {
	if (interval == "default" || interval == "off" || interval == null) {
		interval = "1 minute"
	}
	state.pollInterval = interval
	def pollInterval = getPollInterval(interval)
	runIn(pollInterval, poll)
	logDebug("setPollInterval: interval = ${pollInterval} sec.")
	return interval
}

def rebootDevice() {
	device.updateSetting("rebootDev", [type:"bool", value: false])
	reboot()
	pauseExecution(10000)
	return "REBOOTING DEVICE"
}

def bindUnbind() {
	def message
	if (bind == null ||  getDataValue("feature") == "lightStrip") {
		message = "Getting current bind state"
		getBind()
	} else if (bind == true) {
		if (!parent.kasaToken || parent.userName == null || parent.userPassword == null) {
			message = "Username/pwd not set."
			getBind()
		} else {
			message = "Binding device to the Kasa Cloud."
			setBind(parent.userName, parent.userPassword)
		}
	} else if (bind == false) {
		message = "Unbinding device from the Kasa Cloud."
		setUnbind()
	}
	pauseExecution(5000)
	return message
}

def setBindUnbind(cmdResp) {
	def bindState = true
	if (cmdResp.get_info) {
		if (cmdResp.get_info.binded == 0) { bindState = false }
		logInfo("setBindUnbind: Bind status set to ${bindState}")
		setCommsType(bindState)
	} else if (cmdResp.bind.err_code == 0){
		getBind()
	} else {
		logWarn("setBindUnbind: Unhandled response: ${cmdResp}")
	}
}

def setCommsType(bindState) {
	def commsSettings = [bind: bindState, commsType: "LAN"]
	device.updateSetting("bind", [type:"bool", value: bindState])
	sendEvent(name: "connection", value: "LAN")
	sendEvent(name: "deviceIP", value: getDeviceAddr())
	logInfo("setCommsType: ${commsSettings}")
	if (getDataValue("plugNo") != null) {
		def coordData = [:]
		coordData << [bind: bindState]
		coordData << [connection: "LAN"]
		parent.coordinate("commsData", coordData, getDataValue("deviceId"), getDataValue("plugNo"))
	}
	pauseExecution(1000)
}

def syncName() {
	def message
	if (nameSync == "Hubitat") {
		message = "Hubitat Label Sync"
		setDeviceAlias(device.getLabel())
	} else if (nameSync == "device") {
		message = "Device Alias Sync"
	} else {
		message = "Not Syncing"
	}
	device.updateSetting("nameSync",[type:"enum", value:"none"])
	return message
}

def updateName(response) {
	def name = device.getLabel()
	if (response.alias) {
		name = response.alias
		device.setLabel(name)
	} else if (response.err_code != 0) {
		def msg = "updateName: Name Sync from Hubitat to Device returned an error."
		msg+= "\n\rNote: <b>Some devices do not support syncing name from the hub.</b>\n\r"
		logWarn(msg)
		return
	}
	logInfo("updateName: Hubitat and Kasa device name synchronized to ${name}")
}

def getSysinfo() {
	sendCmd("""{"system":{"get_sysinfo":{}}}""")
}

def getBind() {
	if (getDataValue("deviceIP") == "CLOUD") {
		logWarn("getBind: [status: notRun, reason: [deviceIP: CLOUD]]")
	} else {
		sendLanCmd("""{"cnCloud":{"get_info":{}}}""")
	}
}

def setBind(userName, password) {
	if (getDataValue("deviceIP") == "CLOUD") {
		logWarn("setBind: [status: notRun, reason: [deviceIP: CLOUD]]")
	} else {
		sendLanCmd("""{"cnCloud":{"bind":{"username":"${userName}",""" +
				   """"password":"${password}"}},""" +
				   """"cnCloud":{"get_info":{}}}""")
	}
}

def setUnbind() {
	if (getDataValue("deviceIP") == "CLOUD") {
		logWarn("setUnbind: [status: notRun, reason: [deviceIP: CLOUD]]")
	} else {
		sendLanCmd("""{"cnCloud":{"unbind":""},""" +
				   """"cnCloud":{"get_info":{}}}""")
	}
}

def sysService() {
	def service = "system"
	def feature = getDataValue("feature")
	if (feature.contains("Bulb") || feature == "lightStrip") {
		service = "smartlife.iot.common.system"
	}
	return service
}

def reboot() {
	sendCmd("""{"${sysService()}":{"reboot":{"delay":1}}}""")
}

def setDeviceAlias(newAlias) {
	if (getDataValue("plugNo") != null) {
		sendCmd("""{"context":{"child_ids":["${getDataValue("plugId")}"]},""" +
				""""system":{"set_dev_alias":{"alias":"${device.getLabel()}"}}}""")
	} else {
		sendCmd("""{"${sysService()}":{"set_dev_alias":{"alias":"${device.getLabel()}"}}}""")
	}
}

def updateAttr(attr, value) {
	if (device.currentValue(attr) != value) {
		sendEvent(name: attr, value: value)
	}
}

// ~~~~~ end kasaCommon ~~~~~

// ~~~~~ start kasaCommunications ~~~~~
library (
	name: "kasaCommunications",
	namespace: "kasa",
	author: "Dave Gutheinz",
	description: "Kasa Communications Methods",
	category: "communications",
	documentationLink: ""
)

import groovy.json.JsonSlurper
import org.json.JSONObject

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

def sendCmd(command) {
	state.lastCommand = command
	sendLanCmd(command)
}

///////////////////////////////////
def sendLanCmd(command) {
	logDebug("sendLanCmd: [IP: ${getDeviceAddr()}, cmd: ${command}]")
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
		logWarn("sendLanCmd: LAN Error = ${e}.\n\rNo retry on this error.")
	}
}

def parseUdp(message) {
	def resp = parseLanMessage(message)
	if (resp.type == "LAN_TYPE_UDPCLIENT") {
		def clearResp = inputXOR(resp.payload)
		if (clearResp.length() > 1023) {
			if (clearResp.contains("preferred")) {
				clearResp = clearResp.substring(0,clearResp.indexOf("preferred")-2) + "}}}"
			} else if (clearResp.contains("child_num")) {
				clearResp = clearResp.substring(0,clearResp.indexOf("child_num") -2) + "}}}"
			} else {
				logWarn("parseUdp: udp msg can not be parsed]")
				logDebug("parseUdp: [messageData: ${clearResp}]")
				return
			}
		}
		def cmdResp = new JsonSlurper().parseText(clearResp)
		logDebug("parseUdp: ${cmdResp}")
		distResp(cmdResp)
		setCommsError(false)
	} else {
		logDebug("parseUdp: [error: error, reason: not LAN_TYPE_UDPCLIENT, respType: ${resp.type}]")
		handleCommsError()
	}
}

def close() {
	interfaces.rawSocket.close()
}

def socketStatus(message) {
	if (message != "receive error: Stream closed.") {
		logDebug("socketStatus: Socket Established")
	} else {
		logWarn("socketStatus = ${message}")
	}
}

def parse(message) {
	if (message != null || message != "") {
		def response = state.response.concat(message)
		state.response = response
		extractTcpResp(response)
	}
}

def extractTcpResp(response) {
	def cmdResp
	def clearResp = inputXorTcp(response)
	if (clearResp.endsWith("}}}")) {
		interfaces.rawSocket.close()
		try {
			cmdResp = parseJson(clearResp)
			distResp(cmdResp)
		} catch (e) {
			logWarn("extractTcpResp: [length: ${clearResp.length()}, clearResp: ${clearResp}, comms error: ${e}]")
		}
	} else if (clearResp.length() > 2000) {
		interfaces.rawSocket.close()
	}
}

////////////////////////////////////////
def handleCommsError() {
	Map logData = [:]
	if (state.lastCommand != "") {
		def count = state.errorCount + 1
		state.errorCount = count
		def retry = true
		def cmdData = new JSONObject(state.lastCmd)
		def cmdBody = parseJson(cmdData.cmdBody.toString())
		logData << [count: count, command: state.lastCommand]
		switch (count) {
			case 1:
			case 2:
				sendCmd(state.lastCommand)
				logDebug("handleCommsError: ${logData}")
				break
			case 3:
				logData << [setCommsError: setCommsError(true), status: "retriesDisabled"]
				logError("handleCommsError: ${logData}")
				break
			default:
				break
		}
	}
}

/////////////////////////////////////////////
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

private outputXorTcp(command) {
	def str = ""
	def encrCmd = "000000" + Integer.toHexString(command.length())
 	def key = 0xAB
	for (int i = 0; i < command.length(); i++) {
		str = (command.charAt(i) as byte) ^ key
		key = str
		encrCmd += Integer.toHexString(str)
	}
   	return encrCmd
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
// ~~~~~ end kasaCommunications ~~~~~

// ~~~~~ start commonLogging ~~~~~
library (
	name: "commonLogging",
	namespace: "kasa",
	author: "Dave Gutheinz",
	description: "Common Logging Methods",
	category: "utilities",
	documentationLink: ""
)

//	Logging during development
def listAttributes(trace = false) {
	def attrs = device.getSupportedAttributes()
	def attrList = [:]
	attrs.each {
		def val = device.currentValue("${it}")
		attrList << ["${it}": val]
	}
	if (trace == true) {
		logTrace("Attributes: ${attrList}")
	} else {
		logDebug("Attributes: ${attrList}")
	}
}

def logTrace(msg){
	log.trace "${device.displayName}-${driverVer()}: ${msg}"
}

def logInfo(msg) {
	if (textEnable || infoLog) {
		log.info "${device.displayName}-${driverVer()}: ${msg}"
	}
}

def debugLogOff() {
	if (logEnable) {
		device.updateSetting("logEnable", [type:"bool", value: false])
	}
	logInfo("debugLogOff")
}

def logDebug(msg) {
	if (logEnable || debugLog) {
		log.debug "${device.displayName}-${driverVer()}: ${msg}"
	}
}

def logWarn(msg) { log.warn "${device.displayName}-${driverVer()}: ${msg}" }

// ~~~~~ end commonLogging ~~~~~

// ~~~~~ start kasaPlugs ~~~~~
library (
	name: "kasaPlugs",
	namespace: "kasa",
	author: "Dave Gutheinz",
	description: "Kasa Plug and Switches Common Methods",
	category: "utilities",
	documentationLink: ""
)

def on() { setRelayState(1) }

def off() { setRelayState(0) }

def distResp(response) {
	if (response.system) {
		if (response.system.get_sysinfo) {
			setSysInfo(response.system.get_sysinfo)
		} else if (response.system.set_relay_state) {
			if (getDataValue("model") == "HS210") {
				runIn(2, getSysinfo)
			} else {
				getSysinfo()
			}
		} else if (response.system.reboot) {
			logWarn("distResp: Rebooting device.")
		} else if (response.system.set_dev_alias) {
			updateName(response.system.set_dev_alias)
		} else {
			logDebug("distResp: Unhandled response = ${response}")
		}
	} else if (response["smartlife.iot.dimmer"]) {
		if (response["smartlife.iot.dimmer"].get_dimmer_parameters) {
			setDimmerConfig(response["smartlife.iot.dimmer"])
		} else {
			logDebug("distResp: Unhandled response: ${response["smartlife.iot.dimmer"]}")
		}
	} else if (response.emeter) {
		distEmeter(response.emeter)
	} else if (response.cnCloud) {
		setBindUnbind(response.cnCloud)
	} else {
		logDebug("distResp: Unhandled response = ${response}")
	}
}

def setRelayState(onOff) {
	logDebug("setRelayState: [switch: ${onOff}]")
	if (getDataValue("plugNo") == null) {
		sendCmd("""{"system":{"set_relay_state":{"state":${onOff}}}}""")
	} else {
		sendCmd("""{"context":{"child_ids":["${getDataValue("plugId")}"]},""" +
				""""system":{"set_relay_state":{"state":${onOff}}}}""")
	}
}

// ~~~~~ end kasaPlugs ~~~~~
