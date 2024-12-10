import groovy.json.JsonBuilder
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import groovy.transform.Field
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

/*	Kasa Integration Application
	Copyright Dave Gutheinz
License:  https://github.com/DaveGut/HubitatActive/blob/master/KasaDevices/License.md
===================================================================================================*/

//	App name is used in the lib_tpLink_discovery to check that the device brand is KASA
@Field static final String APP_NAME = "Kasa LAN Integration"
@Field static final String NAMESPACE = "kasa"
@Field static final String VERSION = "1.0.0"

definition(
	name: "Kasa LAN Integration",
	namespace: NAMESPACE,
	author: "Dan Abdinoor",
	description: "Application to install Kasa devices for local-only control.",
	category: "Convenience",
	installOnOpen: true,
	singleInstance: true,
	importUrl: "https://raw.githubusercontent.com/abdinoor/Hubitat/refs/heads/master/Kasa-Local-App.groovy",
	iconUrl: "",
	iconX2Url: ""
)

preferences {
	page(name: "initInstance")
	page(name: "startPage")
	page(name: "lanAddDevicesPage")
	page(name: "manAddDevicesPage")
	page(name: "manAddStart")
	page(name: "cloudAddDevicesPage")
	page(name: "cloudAddStart")
	page(name: "addDevicesPage")
	page(name: "addDevStatus")
	page(name: "listDevices")
	page(name: "kasaAuthenticationPage")
	page(name: "startGetToken")
	page(name: "removeDevicesPage")
	page(name: "listDevicesByIp")
	page(name: "listDevicesByName")
	page(name: "commsTest")
	page(name: "commsTestDisplay")
	page(name: "enterCredentialsPage")
	page(name: "processCredentials")
}

def installed() {
	updated()
}

def updated() {
	logInfo("updated: Updating device configurations")
	unschedule()
	app?.updateSetting("appSetup", [type:"bool", value: false])
	app?.updateSetting("utilities", [type:"bool", value: false])
	app?.updateSetting("debugLog", [type:"bool", value: false])
	app?.removeSetting("pingKasaDevices")
	app?.removeSetting("devAddresses")
	app?.removeSetting("devPort")
	state.remove("lanTest")
	state.remove("addedDevices")
	state.remove("failedAdds")
	state.remove("listDevices")
	configureEnable()
}

def uninstalled() {
    getAllChildDevices().each { 
        deleteChildDevice(it.deviceNetworkId)
    }
}

def initInstance() {
	logDebug("initInstance: Getting external data for the app.")
	if (!debugLog) { app.updateSetting("debugLog", false) }
	state.devices = [:]
	if (!lanSegment) {
		def hub = location.hub
		def hubIpArray = hub.localIP.split('\\.')
		def segments = [hubIpArray[0],hubIpArray[1],hubIpArray[2]].join(".")
		app?.updateSetting("lanSegment", [type:"string", value: segments])
	}
	if (!ports) {
		app?.updateSetting("ports", [type:"string", value: "9999"])
	}
	if (!hostLimits) {
		app?.updateSetting("hostLimits", [type:"string", value: "1, 254"])
	}
	startPage()
}

def startPage() {
	logInfo("starting Kasa Integration")
	if (selectedRemoveDevices) { removeDevices() }
	if (selectedAddDevices) { addDevices() }
	if (debugLog) { runIn(1800, debugOff) }
	try {
		state.segArray = lanSegment.split('\\,')
		state.portArray = ports.split('\\,')
		def rangeArray = hostLimits.split('\\,')
		def array0 = rangeArray[0].toInteger()
		def array1 = array0 + 2
		if (rangeArray.size() > 1) {
			array1 = rangeArray[1].toInteger()
		}
		state.hostArray = [array0, array1]
	} catch (e) {
		logWarn("startPage: Invalid entry for Lan Segements, Host Array Range, or Ports. Resetting to default!")
		def hub = location.hubs[0]
		def hubIpArray = hub.localIP.split('\\.')
		def segments = [hubIpArray[0],hubIpArray[1],hubIpArray[2]].join(".")
		app?.updateSetting("lanSegment", [type:"string", value: segments])
		app?.updateSetting("ports", [type:"string", value: "9999"])
		app?.updateSetting("hostLimits", [type:"string", value: "1, 254"])
	}
	return dynamicPage(name:"startPage",
					   title:"<b>Kasa Hubitat Integration</b>",
					   uninstall: true,
					   install: true) {
		section() {
			paragraph "<b>LAN Configuration</b>:  [LanSegments: ${state.segArray},  " +
				"Ports ${state.portArray},  hostRange: ${state.hostArray}]"
			input "appSetup", "bool",
				title: "<b>Modify LAN Configuration</b>",
				submitOnChange: true,
				defaultalue: false
			if (appSetup) {
				input "lanSegment", "string",
					title: "<b>Lan Segments</b> (ex: 192.168.50, 192,168.01)",
					submitOnChange: true
				input "hostLimits", "string",
					title: "<b>Host Address Range</b> (ex: 5, 100)",
					submitOnChange: true
				input "ports", "string",
					title: "<b>Ports for Port Forwarding</b> (ex: 9999, 8000)",
					submitOnChange: true
			}

			href "lanAddDevicesPage",
				title: "<b>Scan LAN for Kasa devices and add</b>",
				description: "Primary Method to discover and add devices."

			paragraph " "
			href "removeDevicesPage",
				title: "<b>Remove Kasa Devices</b>",
				description: "Select to remove selected Kasa Device from Hubitat."
			paragraph " "

			input "utilities", "bool",
				title: "<b>Kasa Integration Utilities</b>",
				submitOnChange: true,
				defaultalue: false
			if (utilities == true) {
					href "listDevicesByIp",
						title: "<b>Test Device LAN Status and List Devices by IP Address</b>",
						description: "Select to test devices and get list."

				href "listDevicesByName",
					title: "<b>Test Device LAN Status and List Devices by Name</b>",
					description: "Select to test devices and get list."

				href "commsTest", title: "<b>IP Comms Ping Test Tool</b>",
					description: "Select for Ping Test Page."
			}

			input "debugLog", "bool",
				   title: "<b>Enable debug logging for 30 minutes</b>",
				   submitOnChange: true,
				   defaultValue: false
		}
	}
}

def lanAddDevicesPage() {
	logInfo("lanAddDevicesPage")
	addDevicesPage("LAN")
}

def addDevicesPage(discType) {
	logDebug("addDevicesPage: [scan: ${scan}]")
	def action = findDevices()
	def devices = state.devices
	def uninstalledDevices = [:]
	def requiredDrivers = [:]
	devices.each {
		def isChild = getChildDevice(it.value.dni)
		if (!isChild) {
			uninstalledDevices["${it.value.dni}"] = "${it.value.alias}, ${it.value.type}"
			requiredDrivers["${it.value.type}"] = "${it.value.type}"
		}
	}
	uninstalledDevices.sort()
	def reqDrivers = []
	requiredDrivers.each {
		reqDrivers << it.key
	}

	return dynamicPage(name:"addDevicesPage",
					   title: "Add Kasa Devices to Hubitat",
					   nextPage: addDevStatus,
					   install: false) {
		def text = "This page updates every 30 seconds. "
		text += "It can take up to two minutes for all discovered devices to appear."
	 	section() {
			paragraph text
			input ("selectedAddDevices", "enum",
				   required: false,
				   multiple: true,
				   title: "Devices to add (${uninstalledDevices.size() ?: 0} available).\n\t" +
				   "Total Devices: ${devices.size()}",
				   description: "Use the dropdown to select devices.  Then select 'Done'.",
				   options: uninstalledDevices)
		}
	}
}

def addDevStatus() {
	addDevices()
	logInfo("addDevStatus")
	def addMsg = ""
	if (state.addedDevices == null) {
		addMsg += "Added Devices: No devices added."
	} else {
		addMsg += "<b>The following devices were installed:</b>\n"
		state.addedDevices.each{
			addMsg += "\t${it}\n"
		}
	}
	def failMsg = ""
	if (state.failedAdds) {
		failMsg += "<b>The following devices were not installed:</b>\n"
		state.failedAdds.each{
			failMsg += "\t${it}\n"
		}
	}
		
	return dynamicPage(name:"addDeviceStatus",
					   title: "Installation Status",
					   nextPage: listDevices,
					   install: false) {
	 	section() {
			paragraph addMsg
			paragraph failMsg
		}
	}
	app?.removeSetting("selectedAddDevices")
}

def addDevices() {
	logInfo("addDevices: [selectedDevices: ${selectedAddDevices}]")
	def hub = location.hubs[0]
	state.addedDevices = []
	state.failedAdds = []
	selectedAddDevices.each { dni ->
		def isChild = getChildDevice(dni)
		if (!isChild) {
			def device = state.devices.find { it.value.dni == dni }
			def alias = device.value.alias.replaceAll("[\u201C\u201D]", "\"").replaceAll("[\u2018\u2019]", "'").replaceAll("[^\\p{ASCII}]", "")
			def deviceData = [:]
			deviceData["deviceIP"] = device.value.ip
			deviceData["deviceId"] = device.value.deviceId
			deviceData["devicePort"] = device.value.port
			deviceData["model"] = device.value.model
			deviceData["feature"] = device.value.feature
			if (device.value.plugNo) {
				deviceData["plugNo"] = device.value.plugNo
				deviceData["plugId"] = device.value.plugId
			}
			try {
				addChildDevice(
					NAMESPACE,
					device.value.type,
					device.value.dni,
					[
						"label": alias,
						"data" : deviceData
					]
				)
				state.addedDevices << [label: device.value.alias, ip: device.value.ip]
				logInfo("Installed ${device.value.alias}.")
			} catch (error) {
				state.failedAdds << [label: device.value.alias, driver: device.value.type, ip: device.value.ip]
				def msgData = [status: "failedToAdd", label: device.value.alias, driver: device.value.type, ip: device.value.ip]
				msgData << [errorMsg: error]
				logWarn("addDevice: ${msgData}")
			}
		}
		pauseExecution(3000)
	}
	app?.removeSetting("selectedAddDevices")
}

def listDevices() {
	logInfo("listDevices")
	def theList = ""
	def theListTitle= ""
	def devices = state.devices
	if (devices == null) {
		theListTitle += "<b>No devices in the device database.</b>"
	} else {
		theListTitle += "<b>Total Kasa devices: ${devices.size() ?: 0}</b>\n"
		theListTitle +=  "<b>Alias: [Ip:Port, RSSI, Installed?</b>]\n"
		def deviceList = []
		devices.each{
			def dni = it.key
			def installed = "No"
			def isChild = getChildDevice(it.key)
			if (isChild) {
				installed = "Yes"
			}
			deviceList << "<b>${it.value.alias} - ${it.value.model}</b>: [${it.value.ip}:${it.value.port}, ${it.value.rssi}, ${installed}]"
		}
		deviceList.each {
			theList += "${it}\n"
		}
		deviceList.sort()
	}
	return dynamicPage(name:"listDevices",
					   title: "List Kasa Devices from Add Devices",
					   nextPage: startPage,
					   install: false) {
	 	section() {
			paragraph theListTitle
			paragraph "<p style='font-size:14px'>${theList}</p>"
		}
	}
}

def findDevices() {
	def start = state.hostArray.min().toInteger()
	def finish = state.hostArray.max().toInteger() + 1
	logInfo("findDevices: [hostArray: ${state.hostArray}, portArray: ${state.portArray}, pollSegment: ${state.segArray}]")
	def cmdData = outputXOR("""{"system":{"get_sysinfo":{}}}""")
	state.portArray.each {
		def port = it.trim()
		List deviceIPs = []
		state.segArray.each {
			def pollSegment = it.trim()
			logInfo("findDevices: Searching for LAN deivces on IP Segment = ${pollSegment}, port = ${port}")
            for(int i = start; i < finish; i++) {
				deviceIPs.add("${pollSegment}.${i.toString()}")
			}
			sendLanCmd(deviceIPs.join(','), port, cmdData, "getLanData", 15)
			if (encUsername && encPassword) {
				pauseExecution(20000)
				cmdData = "0200000101e51100095c11706d6f58577b22706172616d73223a7b227273615f6b6579223a222d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d5c6e4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b43415145416d684655445279687367797073467936576c4d385c6e54646154397a61586133586a3042712f4d6f484971696d586e2b736b4e48584d525a6550564134627532416257386d79744a5033445073665173795679536e355c6e6f425841674d303149674d4f46736350316258367679784d523871614b33746e466361665a4653684d79536e31752f564f2f47474f795436507459716f384e315c6e44714d77373563334b5a4952387a4c71516f744657747239543337536e50754a7051555a7055376679574b676377716e7338785a657a78734e6a6465534171765c6e3167574e75436a5356686d437931564d49514942576d616a37414c47544971596a5442376d645348562f2b614a32564467424c6d7770344c7131664c4f6a466f5c6e33737241683144744a6b537376376a624f584d51695666453873764b6877586177717661546b5658382f7a4f44592b2f64684f5374694a4e6c466556636c35585c6e4a514944415141425c6e2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d5c6e227d7d"
				sendLanCmd(deviceIPs.join(','), "20002", cmdData, "getSmartLanData", 15)
			}
		}
	}
	pauseExecution(20000)
	updateChildren()
	return
}

def getLanData(response) {
	if (response instanceof Map) {
		def lanData = parseLanData(response)
		if (lanData.error) { return }
		def cmdResp = lanData.cmdResp
		if (cmdResp.system) {
			cmdResp = cmdResp.system
		}
		parseDeviceData(cmdResp, lanData.ip, lanData.port)
	} else {
		response.each {
			def lanData = parseLanData(it)
			if (lanData.error) { return }
			def cmdResp = lanData.cmdResp
			if (cmdResp.system) {
				cmdResp = cmdResp.system
			}
			parseDeviceData(cmdResp, lanData.ip, lanData.port)
			if (lanData.cmdResp.children) {
				pauseExecution(120)
			} else {
				pauseExecution(40)
			}
		}
	}
}

def parseSmartDeviceData(devData) {
	def dni = devData.mac.replaceAll("-", "")
	Map deviceData = [dni: dni]
	String deviceType = devData.type
	byte[] plainBytes = devData.nickname.decodeBase64()
	String alias = new String(plainBytes)
	deviceData << [alias: alias]
	deviceData << [model: devData.model]
	deviceData << [ip: devData.ip]
	deviceData << [deviceId: devData.device_id]
	String capability = "newType"
	String feature
	if (deviceType == "SMART.KASASWITCH" || deviceType == "SMART.KASAPLUG") {
		capability = "plug"
		if (devData.brightness) {
			capability = "plug_dimmer"
		}
		if (devData.power_protection_status) {
			capability = "plug_em"
		}
	} else if (deviceType == "SMART.KASAHUB") {
		capability = "hub"
	}
	String type = "kasaSmart_${capability}"
	deviceData << [type: type]
	deviceData << [capability: capability]
	state.devices << ["${dni}": deviceData]
	logDebug("parseSmartDeviceData: [${dni}: ${deviceData}]")
}

def parseDeviceData(cmdResp, ip = "CLOUD", port = "CLOUD") {
	logDebug("parseDeviceData: ${cmdResp} //  ${ip} // ${port}")
	def dni
	if (cmdResp.mic_mac) {
		dni = cmdResp.mic_mac
	} else {
		dni = cmdResp.mac.replace(/:/, "")
	}
	def devices = state.devices
	def kasaType
	if (cmdResp.mic_type) {
		kasaType = cmdResp.mic_type
	} else {
		kasaType = cmdResp.type
	}
	def type = "Kasa LAN Device"
	def feature = cmdResp.feature
	if (kasaType == "IOT.SMARTPLUGSWITCH") {
		if (cmdResp.dev_name && cmdResp.dev_name.contains("Dimmer")) {
			feature = "dimmingSwitch"
			type = "Kasa LAN Device"
		}		
	}
	def model = cmdResp.model
	def alias = cmdResp.alias
	def rssi = cmdResp.rssi
	def deviceId = cmdResp.deviceId
	def plugNo
	def plugId
	if (cmdResp.children) {
		def childPlugs = cmdResp.children
		childPlugs.each {
			plugNo = it.id
			plugNo = it.id.substring(it.id.length() - 2)
			def childDni = "${dni}${plugNo}"
			plugId = "${deviceId}${plugNo}"
			alias = it.alias
			def device = createDevice(childDni, ip, port, rssi, type, feature, model, alias, deviceId, plugNo, plugId)
			devices["${childDni}"] = device
			logDebug("parseDeviceData: ${type} ${alias} (${ip}) added to devices array.")
		}
	} else if (model == "HS300") {
		def parentAlias = alias
		for(int i = 0; i < 6; i++) {
			plugNo = "0${i.toString()}"
			def childDni = "${dni}${plugNo}"
			plugId = "${deviceId}${plugNo}"
			def child = getChildDevice(childDni)
			if (child) {
				alias = child.device.getLabel()
			} else {
				alias = "${parentAlias}_${plugNo}_TEMP"
			}
			def device = createDevice(childDni, ip, port, rssi, type, feature, model, alias, deviceId, plugNo, plugId)
			devices["${childDni}"] = device
			logDebug("parseDeviceData: ${type} ${alias} (${ip}) added to devices array.")
		}
	} else {
		def device = createDevice(dni, ip, port, rssi, type, feature, model, alias, deviceId, plugNo, plugId)
		devices["${dni}"] = device
		logDebug("parseDeviceData: ${type} ${alias} (${ip}) added to devices array.")
	}
}

def createDevice(dni, ip, port, rssi, type, feature, model, alias, deviceId, plugNo, plugId) {
	logDebug("createDevice: dni = ${dni}")
	def device = [:]
	device["dni"] = dni
	device["ip"] = ip
	device["port"] = port
	device["type"] = type
	device["rssi"] = rssi
	device["feature"] = feature
	device["model"] = model
	device["alias"] = alias
	device["deviceId"] = deviceId
	if (plugNo != null) {
		device["plugNo"] = plugNo
		device["plugId"] = plugId
	}
	return device
}

def removeDevicesPage() {
	logInfo("removeDevicesPage")
	def devices = state.devices
	def installedDevices = [:]
	devices.each {
		def installed = false
		def isChild = getChildDevice(it.value.dni)
		if (isChild) {
			installedDevices["${it.value.dni}"] = "${it.value.alias}, type = ${it.value.type}, dni = ${it.value.dni}"
		}
	}
	logDebug("removeDevicesPage: newDevices = ${newDevices}")
	return dynamicPage(name:"removedDevicesPage",
					   title:"<b>Remove Kasa Devices from Hubitat</b>",
					   nextPage: startPage,
					   install: false) {
		section("Select Devices to Remove from Hubitat") {
			input ("selectedRemoveDevices", "enum",
				   required: false,
				   multiple: true,
				   title: "Devices to remove (${installedDevices.size() ?: 0} available)",
				   description: "Use the dropdown to select devices.  Then select 'Done'.",
				   options: installedDevices)
		}
	}
}

def removeDevices() {
	logDebug("removeDevices: ${selectedRemoveDevices}")
	def devices = state.devices
	selectedRemoveDevices.each { dni ->
		def device = state.devices.find { it.value.dni == dni }
		def isChild = getChildDevice(dni)
		if (isChild) {
			try {
				deleteChildDevice(dni)
				logInfo("Deleted ${device.value.alias}")
			} catch (error) {
				logWarn("Failed to delet ${device.value.alias}.")
			}
		}
	}
	app?.removeSetting("selectedRemoveDevices")
}

def listDevicesByIp() {
	logInfo("listDevicesByIp")
	def deviceList = getDeviceList("ip")
	deviceList.sort()
	def theListTitle = "<b>Total Kasa devices: ${deviceList.size() ?: 0}</b>\n"
	theListTitle +=  "<b>[Ip:Port:  Alias, DriverVersion, Installed?</b>]\n"
	String theList = ""
	deviceList.each {
		theList += "${it}\n"
	}
	return dynamicPage(name:"listDevicesByIp",
					   title: "List Kasa Devices by IP",
					   nextPage: startPage,
					   install: false) {
	 	section() {
			paragraph theListTitle
			paragraph "<p style='font-size:14px'>${theList}</p>"
		}
	}
}

def listDevicesByName() {
	logInfo("listDevicesByName")
	def deviceList = getDeviceList("name")
	deviceList.sort()
	def theListTitle = "<b>Total Kasa devices: ${deviceList.size() ?: 0}</b>\n"
	theListTitle += "<b>Alias: Ip:Port, DriverVersion, Installed?]</b>\n"
	String theList = ""
	deviceList.each {
		theList += "${it}\n"
	}
	return dynamicPage(name:"listDevicesByName",
					   title: "List Kasa Devices by Name",
					   nextPage: startPage,
					   install: false) {
	 	section() {
			paragraph theListTitle
			paragraph "<p style='font-size:14px'>${theList}</p>"
		}
	}
}

def getDeviceList(sortType) {
	state.devices = [:]
	def getData = findDevices()
	def devices = state.devices
	def deviceList = []
	if (devices == null) {
		deviceList << "<b>No Devices in devices.</b>]"
	} else {
		devices.each{
			def dni = it.key
			def result = ["Failed", "n/a"]
			def driverVer = "ukn"
			def installed = "No"
			def isChild = getChildDevice(it.key)
			if (isChild) {
				driverVer = isChild.driverVer()
				installed = "Yes"
			}
			if (sortType == "ip") {
				deviceList << "<b>${it.value.ip}:${it.value.port}</b>: ${it.value.alias}, ${driverVer}, ${installed}]"
			} else {
				deviceList << "<b>${it.value.alias}</b>: ${it.value.ip}:${it.value.port}, ${driverVer}, ${installed}]"
			}
		}
	}
	return deviceList
}

def commsTest() {
	logInfo("commsTest")
	return dynamicPage(name:"commsTest",
					   title: "IP Communications Test",
					   nextPage: startPage,
					   install: false) {
	 	section() {
			def note = "This test measures ping from this Hub to any device on your  " +
				"LAN (wifi and connected). You enter your Router's IP address, a " +
				"non-Kasa device (other hub if you have one), and select the Kasa " +
				"devices to ping. (Each ping will take about 3 seconds)."
			paragraph note
			input "routerIp", "string",
				title: "<b>IP Address of your Router</b>",
				required: false,
				submitOnChange: true
			input "nonKasaIp", "string",
				title: "<b>IP Address of non-Kasa LAN device (other Hub?)</b>",
				required: false,
				submitOnChange: true

			def devices = state.devices
			def kasaDevices = [:]
			devices.each {
				kasaDevices["${it.value.dni}"] = "${it.value.alias}, ${it.value.ip}"
 			}
			input ("pingKasaDevices", "enum",
				   required: false,
				   multiple: true,
				   title: "Kasa devices to ping (${kasaDevices.size() ?: 0} available).",
				   description: "Use the dropdown to select devices.",
				   options: kasaDevices)
			paragraph "Test will take approximately 5 seconds per device."
			href "commsTestDisplay", title: "<b>Ping Selected Devices</b>",
				description: "Click to Test IP Comms."

			href "startPage", title: "<b>Exit without Testing</b>",
				description: "Return to start page without attempting"
		}
	}
}

def commsTestDisplay() {
	logDebug("commsTestDisplay: [routerIp: ${routerIp}, nonKasaIp: ${nonKasaIp}, kasaDevices: ${pingKasaDevices}]")
	def pingResults = []
	def pingResult
	if (routerIp != null) {
		pingResult = sendPing(routerIp, 5)
		pingResults << "<b>Router</b>: ${pingResult}"
	}
	if (nonKasaIp != null) {
		pingResult = sendPing(nonKasaIp, 5)
		pingResults << "<b>nonKasaDevice</b>: ${pingResult}"
	}
	def devices = state.devices
	if (pingKasaDevices != null) {
		pingKasaDevices.each {dni ->
			def device = devices.find { it.value.dni == dni }
			pingResult = sendPing(device.value.ip, 5)
			pingResults << "<b>${device.value.alias}</b>: ${pingResult}"
		}
	}
	def pingList = ""
	pingResults.each {
		pingList += "${it}\n"
	}
	return dynamicPage(name:"commsTestDisplay",
					   title: "Ping Testing Result",
					   nextPage: commsTest,
					   install: false) {
		section() {
			def note = "<b>Expectations</b>:\na.\tAll devices have similar ping results." +
				"\nb.\tAll pings are less than 1000 ms.\nc.\tSuccess is 100." +
				"\nIf not, test again to verify bad results." +
				"\nAll times are in ms. Success is percent of 5 total tests."
			paragraph note
			paragraph "<p style='font-size:14px'>${pingList}</p>"
		}
	}
}

def sendPing(ip, count = 3) {
	hubitat.helper.NetworkUtils.PingData pingData = hubitat.helper.NetworkUtils.ping(ip, count)
	def success = "nullResults"
	def minTime = "n/a"
	def maxTime = "n/a"
	if (pingData) {
		success = (100 * pingData.packetsReceived.toInteger()  / count).toInteger()
		minTime = pingData.rttMin
		maxTime = pingData.rttMax
	}
	def pingResult = [ip: ip, min: minTime, max: maxTime, success: success]
	return pingResult
}

def updateConfigurations() {
	def msg = ""
	if (configureEnabled) {
		app?.updateSetting("configureEnabled", [type:"bool", value: false])
		configureChildren()
		runIn(600, configureEnable)
		msg += "Updating App and device configurations"
	} else {
		msg += "<b>Not executed</b>.  Method run within last 10 minutes."
	}
	logInfo("updateConfigurations: ${msg}")
	return msg
}

def configureEnable() {
	logDebug("configureEnable: Enabling configureDevices")
	app?.updateSetting("configureEnabled", [type:"bool", value: true])
}

def configureChildren() {
	def fixConnect = fixConnection(true)
	def children = getChildDevices()
	children.each {
		it.updated()
	}
}

def fixConnection(force = false) {
	def msg = "fixConnection: "
	if (pollEnabled == true || pollEnabled == null || force == true) {
		msg += execFixConnection()
		msg += "Checking and updating all device IPs."
	} else {
		msg += "[pollEnabled: false]"
	}
	logInfo(msg)
	return msg
}

def pollEnable() {
	logDebug("pollEnable: Enabling IP check from device error.")
	app?.updateSetting("pollEnabled", [type:"bool", value: true])
}

def execFixConnection() {
	def message = [:]
	app?.updateSetting("pollEnabled", [type:"bool", value: false])
	runIn(900, pollEnable)
	def pollDevs = findDevices()
	message << [segmentArray: state.segArray, hostArray: state.hostArray, portArray: state.portArray]
	def tokenUpd = false
	if (kasaToken && userName != "") {
		def token = getToken()
		tokenUpd = true
	}
	message << [tokenUpdated: tokenUpd]
	return message
}

def updateChildren() {
	def devices = state.devices
	devices.each {
		def child = getChildDevice(it.key)
		if (child) {
			if (it.value.ip != null || it.value.ip != "" || it.value.ip != "CLOUD") {
				child.updateDataValue("deviceIP", it.value.ip)
				child.updateDataValue("devicePort", it.value.port.toString())
				def logData = [deviceIP: it.value.ip,port: it.value.port]
				logDebug("updateChildDeviceData: [${it.value.alias}: ${logData}]")
			}
		}
	}
}

private sendLanCmd(ip, port, cmdData, action, commsTo = 5) {
	Map data = [ip: ip, port: port, action: action]
	logInfo("sendLanCmd: ${data}")
	def myHubAction = new hubitat.device.HubAction(
		cmdData,
		hubitat.device.Protocol.LAN,
		[type: hubitat.device.HubAction.Type.LAN_TYPE_UDPCLIENT,
		 destinationAddress: "${ip}:${port}",
		 encoding: hubitat.device.HubAction.Encoding.HEX_STRING,
		 parseWarning: true,
		 timeout: commsTo,
		 callback: action])
	try {
		sendHubCommand(myHubAction)
	} catch (error) {
		logWarn("sendLanCmd: command failed. Error = ${error}")
	}
}

def parseLanData(response) {
	def resp = parseLanMessage(response.description)
	if (resp.type == "LAN_TYPE_UDPCLIENT") {
		def ip = convertHexToIp(resp.ip)
		def port = convertHexToInt(resp.port)
		def clearResp = inputXOR(resp.payload)
		def cmdResp
		try {
			cmdResp = new JsonSlurper().parseText(clearResp).system.get_sysinfo
		} catch (err) {
			if (clearResp.contains("child_num")) {
				clearResp = clearResp.substring(0,clearResp.indexOf("child_num")-2) + "}}}"
			} else if (clearResp.contains("children")) {
				clearResp = clearResp.substring(0,clearResp.indexOf("children")-2) + "}}}"
			} else if (clearResp.contains("preferred")) {
				clearResp = clearResp.substring(0,clearResp.indexOf("preferred")-2) + "}}}"
			} else {
				logWarn("parseLanData: [error: msg too long, data: ${clearResp}]")
				return [error: "error", reason: "message to long"]
			}
			cmdResp = new JsonSlurper().parseText(clearResp).system.get_sysinfo
		}
		return [cmdResp: cmdResp, ip: ip, port: port]
	} else {
		return [error: "error", reason: "not LAN_TYPE_UDPCLIENT", respType: resp.type]
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
	for(int i = 0; i < strBytes.length-1; i++) {
		nextKey = (byte)Integer.parseInt(strBytes[i], 16)	// could be negative
		XORtemp = nextKey ^ key
		key = nextKey
		cmdResponse += new String(XORtemp)
	}
	return cmdResponse
}

private String convertHexToIp(hex) {
	[convertHexToInt(hex[0..1]),convertHexToInt(hex[2..3]),convertHexToInt(hex[4..5]),convertHexToInt(hex[6..7])].join(".")
}
private Integer convertHexToInt(hex) {
	Integer.parseInt(hex,16)
}

def createMultiCmd(requests) {
	Map cmdBody = [
		method: "multipleRequest",
		params: [requests: requests]]
	return cmdBody
}

def asyncPassthrough(cmdBody, method, action) {
	if (devIp == null) { devIp = getDataValue("deviceIP") }	//	used for Kasa Compatibility
	Map cmdData = [cmdBody: cmdBody, method: method, action: action]
	state.lastCmd = cmdData
	logDebug("asyncPassthrough: ${cmdData}")
	def uri = "http://${getDataValue("deviceIP")}/app?token=${getDataValue("deviceToken")}"
	Map reqBody = createReqBody(cmdBody)
	asyncPost(uri, reqBody, action, getDataValue("deviceCookie"), method)
}

def syncPassthrough(cmdBody) {
	if (devIp == null) { devIp = getDataValue("deviceIP") }	//	used for Kasa Compatibility
	Map logData = [cmdBody: cmdBody]
	def uri = "http://${getDataValue("deviceIP")}/app?token=${getDataValue("deviceToken")}"
	Map reqBody = createReqBody(cmdBody)
	def resp = syncPost(uri, reqBody, getDataValue("deviceCookie"))
	def cmdResp = "ERROR"
	if (resp.status == "OK") {
		try {
			cmdResp = new JsonSlurper().parseText(decrypt(resp.resp.data.result.response))
			logData << [status: "OK"]
		} catch (err) {
			logData << [status: "cryptoError", error: "Error decrypting response", data: err]
		}
	} else {
		logData << [status: "postJsonError", postJsonData: resp]
	}
	if (logData.status == "OK") {
		logDebug("syncPassthrough: ${logData}")
	} else {
		logWarn("syncPassthrough: ${logData}")
	}
	return cmdResp
}

def createReqBody(cmdBody) {
	def cmdStr = JsonOutput.toJson(cmdBody).toString()
	Map reqBody = [method: "securePassthrough",
				   params: [request: encrypt(cmdStr)]]
	return reqBody
}

//	===== Sync comms for device update =====
def syncPost(uri, reqBody, cookie=null) {
	def reqParams = [
		uri: uri,
		headers: [
			Cookie: cookie
		],
		body : new JsonBuilder(reqBody).toString()
	]
	logDebug("syncPost: [cmdParams: ${reqParams}]")
	Map respData = [:]
	try {
		httpPostJson(reqParams) {resp ->
			if (resp.status == 200 && resp.data.error_code == 0) {
				respData << [status: "OK", resp: resp]
			} else {
				respData << [status: "lanDataError", respStatus: resp.status,
					errorCode: resp.data.error_code]
			}
		}
	} catch (err) {
		respData << [status: "HTTP Failed", data: err]
	}
	return respData
}

def asyncPost(uri, reqBody, parseMethod, cookie=null, reqData=null) {
	Map logData = [:]
	def reqParams = [
		uri: uri,
		requestContentType: 'application/json',
		contentType: 'application/json',
		headers: [
			Cookie: cookie
		],
		timeout: 4,
		body : new groovy.json.JsonBuilder(reqBody).toString()
	]
	try {
		asynchttpPost(parseMethod, reqParams, [data: reqData])
		logData << [status: "OK"]
	} catch (e) {
		logData << [status: e, reqParams: reqParams]
	}
	if (logData.status == "OK") {
		logDebug("asyncPost: ${logData}")
	} else {
		logWarn("asyncPost: ${logData}")
		handleCommsError()
	}
}

def parseData(resp) {
	def logData = [:]
	if (resp.status == 200 && resp.json.error_code == 0) {
		def cmdResp
		try {
			cmdResp = new JsonSlurper().parseText(decrypt(resp.json.result.response))
			setCommsError(false)
		} catch (err) {
			logData << [status: "cryptoError", error: "Error decrypting response", data: err]
		}
		if (cmdResp != null && cmdResp.error_code == 0) {
			logData << [status: "OK", cmdResp: cmdResp]
		} else {
			logData << [status: "deviceDataError", cmdResp: cmdResp]
		}
	} else {
		logData << [status: "lanDataError"]
	}
	if (logData.status == "OK") {
		logDebug("parseData: ${logData}")
	} else {
		logWarn("parseData: ${logData}")
		handleCommsError()
	}
	return logData
}

def handleCommsError() {
	Map logData = [:]
	if (state.lastCommand != "") {
		def count = state.errorCount + 1
		state.errorCount = count
		def cmdData = new JSONObject(state.lastCmd)
		def cmdBody = parseJson(cmdData.cmdBody.toString())
		logData << [count: count, command: cmdData]
		switch (count) {
			case 1:
				asyncPassthrough(cmdBody, cmdData.method, cmdData.action)
				logData << [status: "commandRetry"]
				logDebug("handleCommsError: ${logData}")
				break
			case 2:
				logData << [deviceLogin: deviceLogin()]
				Map data = [cmdBody: cmdBody, method: cmdData.method, action:cmdData.action]
				runIn(2, delayedPassThrough, [data:data])
				logData << [status: "newLogin and commandRetry"]
				logWarn("handleCommsError: ${logData}")
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

def delayedPassThrough(data) {
	asyncPassthrough(data.cmdBody, data.method, data.action)
}

def setCommsError(status) {
	if (!status) {
		updateAttr("commsError", false)
		state.errorCount = 0
	} else {
		updateAttr("commsError", true)
		return "commsErrorSet"
	}
}


def securityPreferences() {
	input ("aesKey", "password", title: "Storage for the AES Key")
}

//	===== Device Login Core =====
def handshake(devIp) {
	def rsaKeys = getRsaKeys()
	Map handshakeData = [method: "handshakeData", rsaKeys: rsaKeys.keyNo]
	def pubPem = "-----BEGIN PUBLIC KEY-----\n${rsaKeys.public}-----END PUBLIC KEY-----\n"
	Map cmdBody = [ method: "handshake", params: [ key: pubPem]]
	def uri = "http://${devIp}/app"
	def respData = syncPost(uri, cmdBody)
	if (respData.status == "OK") {
		String deviceKey = respData.resp.data.result.key
		try {
			def cookieHeader = respData.resp.headers["set-cookie"].toString()
			def cookie = cookieHeader.substring(cookieHeader.indexOf(":") +1, cookieHeader.indexOf(";"))
			handshakeData << [cookie: cookie]
		} catch (err) {
			handshakeData << [respStatus: "FAILED", check: "respData.headers", error: err]
		}
		def aesArray = readDeviceKey(deviceKey, rsaKeys.private)
		handshakeData << [aesKey: aesArray]
		if (aesArray == "ERROR") {
			handshakeData << [respStatus: "FAILED", check: "privateKey"]
		} else {
			handshakeData << [respStatus: "OK"]
		}
	} else {
		handshakeData << [respStatus: "FAILED", check: "pubPem. devIp", respData: respData]
	}
	if (handshakeData.respStatus == "OK") {
		logDebug("handshake: ${handshakeData}")
	} else {
		logWarn("handshake: ${handshakeData}")
	}
	return handshakeData
}

def readDeviceKey(deviceKey, privateKey) {
	def response = "ERROR"
	def logData = [:]
	try {
		byte[] privateKeyBytes = privateKey.decodeBase64()
		byte[] deviceKeyBytes = deviceKey.getBytes("UTF-8").decodeBase64()
    	Cipher instance = Cipher.getInstance("RSA/ECB/PKCS1Padding")
		instance.init(2, KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes)))
		byte[] cryptoArray = instance.doFinal(deviceKeyBytes)
		response = cryptoArray
		logData << [cryptoArray: "REDACTED for logs", status: "OK"]
		logDebug("readDeviceKey: ${logData}")
	} catch (err) {
		logData << [status: "READ ERROR", data: err]
		logWarn("readDeviceKey: ${logData}")
	}
	return response
}

def loginDevice(cookie, cryptoArray, credentials, devIp) {
	Map tokenData = [method: "loginDevice"]
	def uri = "http://${devIp}/app"
	Map cmdBody = [method: "login_device",
				   params: [password: credentials.encPassword,
							username: credentials.encUsername],
				   requestTimeMils: 0]
	def cmdStr = JsonOutput.toJson(cmdBody).toString()
	Map reqBody = [method: "securePassthrough", params: [request: encrypt(cmdStr, cryptoArray)]]
	def respData = syncPost(uri, reqBody, cookie)
	if (respData.status == "OK") {
		if (respData.resp.data.error_code == 0) {
			try {
				def cmdResp = decrypt(respData.resp.data.result.response, cryptoArray)
				cmdResp = new JsonSlurper().parseText(cmdResp)
				if (cmdResp.error_code == 0) {
					tokenData << [respStatus: "OK", token: cmdResp.result.token]
				} else {
					tokenData << [respStatus: "Error from device",
								  check: "cryptoArray, credentials", data: cmdResp]
				}
			} catch (err) {
				tokenData << [respStatus: "Error parsing", error: err]
			}
		} else {
			tokenData << [respStatus: "Error in respData.data", data: respData.data]
		}
	} else {
		tokenData << [respStatus: "Error in respData", data: respData]
	}
	if (tokenData.respStatus == "OK") {
		logDebug("handshake: ${tokenData}")
	} else {
		logWarn("handshake: ${tokenData}")
	}
	return tokenData
}

//	===== AES Methods =====
//def encrypt(plainText, keyData) {
def encrypt(plainText, keyData = null) {
	if (keyData == null) {
		keyData = new JsonSlurper().parseText(aesKey)
	}
	byte[] keyenc = keyData[0..15]
	byte[] ivenc = keyData[16..31]

	def cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
	SecretKeySpec key = new SecretKeySpec(keyenc, "AES")
	IvParameterSpec iv = new IvParameterSpec(ivenc)
	cipher.init(Cipher.ENCRYPT_MODE, key, iv)
	String result = cipher.doFinal(plainText.getBytes("UTF-8")).encodeBase64().toString()
	return result.replace("\r\n","")
}

def decrypt(cypherText, keyData = null) {
	if (keyData == null) {
		keyData = new JsonSlurper().parseText(aesKey)
	}
	byte[] keyenc = keyData[0..15]
	byte[] ivenc = keyData[16..31]

    byte[] decodedBytes = cypherText.decodeBase64()
    def cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    SecretKeySpec key = new SecretKeySpec(keyenc, "AES")
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivenc))
	String result = new String(cipher.doFinal(decodedBytes), "UTF-8")
	return result
}

//	===== RSA Key Methods =====
def getRsaKeys() {
	def keyNo = Math.round(5 * Math.random()).toInteger()
	def keyData = keyData()
	def RSAKeys = keyData.find { it.keyNo == keyNo }
	return RSAKeys
}

def keyData() {
/*	User Note.  You can update these keys at you will using the site:
		https://www.devglan.com/online-tools/rsa-encryption-decryption
	with an RSA Key Size: 1024 bit
	This is at your risk.*/
	return [
		[
			keyNo: 0,
			public: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDGr/mHBK8aqx7UAS+g+TuAvE3J2DdwsqRn9MmAkjPGNon1ZlwM6nLQHfJHebdohyVqkNWaCECGXnftnlC8CM2c/RujvCrStRA0lVD+jixO9QJ9PcYTa07Z1FuEze7Q5OIa6pEoPxomrjxzVlUWLDXt901qCdn3/zRZpBdpXzVZtQIDAQAB",
			private: "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAMav+YcErxqrHtQBL6D5O4C8TcnYN3CypGf0yYCSM8Y2ifVmXAzqctAd8kd5t2iHJWqQ1ZoIQIZed+2eULwIzZz9G6O8KtK1EDSVUP6OLE71An09xhNrTtnUW4TN7tDk4hrqkSg/GiauPHNWVRYsNe33TWoJ2ff/NFmkF2lfNVm1AgMBAAECgYEAocxCHmKBGe2KAEkq+SKdAxvVGO77TsobOhDMWug0Q1C8jduaUGZHsxT/7JbA9d1AagSh/XqE2Sdq8FUBF+7vSFzozBHyGkrX1iKURpQFEQM2j9JgUCucEavnxvCqDYpscyNRAgqz9jdh+BjEMcKAG7o68bOw41ZC+JyYR41xSe0CQQD1os71NcZiMVqYcBud6fTYFHZz3HBNcbzOk+RpIHyi8aF3zIqPKIAh2pO4s7vJgrMZTc2wkIe0ZnUrm0oaC//jAkEAzxIPW1mWd3+KE3gpgyX0cFkZsDmlIbWojUIbyz8NgeUglr+BczARG4ITrTV4fxkGwNI4EZxBT8vXDSIXJ8NDhwJBAIiKndx0rfg7Uw7VkqRvPqk2hrnU2aBTDw8N6rP9WQsCoi0DyCnX65Hl/KN5VXOocYIpW6NAVA8VvSAmTES6Ut0CQQCX20jD13mPfUsHaDIZafZPhiheoofFpvFLVtYHQeBoCF7T7vHCRdfl8oj3l6UcoH/hXMmdsJf9KyI1EXElyf91AkAvLfmAS2UvUnhX4qyFioitjxwWawSnf+CewN8LDbH7m5JVXJEh3hqp+aLHg1EaW4wJtkoKLCF+DeVIgbSvOLJw"
		],[
			keyNo: 1,
			public: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCshy+qBKbJNefcyJUZ/3i+3KyLji6XaWEWvebUCC2r9/0jE6hc89AufO41a13E3gJ2es732vaxwZ1BZKLy468NnL+tg6vlQXaPkDcdunQwjxbTLNL/yzDZs9HRju2lJnupcksdJWBZmjtztMWQkzBrQVeSKzSTrKYK0s24EEXmtQIDAQAB",
			private: "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKyHL6oEpsk159zIlRn/eL7crIuOLpdpYRa95tQILav3/SMTqFzz0C587jVrXcTeAnZ6zvfa9rHBnUFkovLjrw2cv62Dq+VBdo+QNx26dDCPFtMs0v/LMNmz0dGO7aUme6lySx0lYFmaO3O0xZCTMGtBV5IrNJOspgrSzbgQRea1AgMBAAECgYBSeiX9H1AkbJK1Z2ZwEUNF6vTJmmUHmScC2jHZNzeuOFVZSXJ5TU0+jBbMjtE65e9DeJ4suw6oF6j3tAZ6GwJ5tHoIy+qHRV6AjA8GEXjhSwwVCyP8jXYZ7UZyHzjLQAK+L0PvwJY1lAtns/Xmk5GH+zpNnhEmKSZAw23f7wpj2QJBANVPQGYT7TsMTDEEl2jq/ZgOX5Djf2VnKpPZYZGsUmg1hMwcpN/4XQ7XOaclR5TO/CJBJl3UCUEVjdrR1zdD8g8CQQDPDoa5Y5UfhLz4Ja2/gs2UKwO4fkTqqR6Ad8fQlaUZ55HINHWFd8FeERBFgNJzszrzd9BBJ7NnZM5nf2OPqU77AkBLuQuScSZ5HL97czbQvwLxVMDmLWyPMdVykOvLC9JhPgZ7cvuwqnlWiF7mEBzeHbBx9JDLJDd4zE8ETBPLgapPAkAHhCR52FaSdVQSwfNjr1DdHw6chODlj8wOp8p2FOiQXyqYlObrOGSpkH8BtuJs1sW+DsxdgR5vE2a2tRYdIe0/AkEAoQ5MzLcETQrmabdVCyB9pQAiHe4yY9e1w7cimsLJOrH7LMM0hqvBqFOIbSPrZyTp7Ie8awn4nTKoZQtvBfwzHw=="
		],[
			keyNo: 2,
			public: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCBeqRy4zAOs63Sc5yc0DtlFXG1stmdD6sEfUiGjlsy0S8aS8X+Qcjcu5AK3uBBrkVNIa8djXht1bd+pUof5/txzWIMJw9SNtNYqzSdeO7cCtRLzuQnQWP7Am64OBvYkXn2sUqoaqDE50LbSQWbuvZw0Vi9QihfBYGQdlrqjCPUsQIDAQAB",
			private: "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIF6pHLjMA6zrdJznJzQO2UVcbWy2Z0PqwR9SIaOWzLRLxpLxf5ByNy7kAre4EGuRU0hrx2NeG3Vt36lSh/n+3HNYgwnD1I201irNJ147twK1EvO5CdBY/sCbrg4G9iRefaxSqhqoMTnQttJBZu69nDRWL1CKF8FgZB2WuqMI9SxAgMBAAECgYBBi2wkHI3/Y0Xi+1OUrnTivvBJIri2oW/ZXfKQ6w+PsgU+Mo2QII0l8G0Ck8DCfw3l9d9H/o2wTDgPjGzxqeXHAbxET1dS0QBTjR1zLZlFyfAs7WO8tDKmHVroUgqRkJgoQNQlBSe1E3e7pTgSKElzLuALkRS6p1jhzT2wu9U04QJBAOFr/G36PbQ6NmDYtVyEEr3vWn46JHeZISdJOsordR7Wzbt6xk6/zUDHq0OGM9rYrpBy7PNrbc0JuQrhfbIyaHMCQQCTCvETjXCMkwyUrQT6TpxVzKEVRf1rCitnNQCh1TLnDKcCEAnqZT2RRS3yNXTWFoJrtuEHMGmwUrtog9+ZJBlLAkEA2qxdkPY621XJIIO404mPgM7rMx4F+DsE7U5diHdFw2fO5brBGu13GAtZuUQ7k2W1WY0TDUO+nTN8XPDHdZDuvwJABu7TIwreLaKZS0FFJNAkCt+VEL22Dx/xn/Idz4OP3Nj53t0Guqh/WKQcYHkowxdYmt+KiJ49vXSJJYpiNoQ/NQJAM1HCl8hBznLZLQlxrCTdMvUimG3kJmA0bUNVncgUBq7ptqjk7lp5iNrle5aml99foYnzZeEUW6jrCC7Lj9tg+w=="
		],[
			keyNo: 3,
			public: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCFYaoMvv5kBxUUbp4PQyd7RoZlPompsupXP2La0qGGxacF98/88W4KNUqLbF4X5BPqxoEA+VeZy75qqyfuYbGQ4fxT6usE/LnzW8zDY/PjhVBht8FBRyAUsoYAt3Ip6sDyjd9YzRzUL1Q/OxCgxz5CNETYxcNr7zfMshBHDmZXMQIDAQAB",
			private: "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIVhqgy+/mQHFRRung9DJ3tGhmU+iamy6lc/YtrSoYbFpwX3z/zxbgo1SotsXhfkE+rGgQD5V5nLvmqrJ+5hsZDh/FPq6wT8ufNbzMNj8+OFUGG3wUFHIBSyhgC3cinqwPKN31jNHNQvVD87EKDHPkI0RNjFw2vvN8yyEEcOZlcxAgMBAAECgYA3NxjoMeCpk+z8ClbQRqJ/e9CC9QKUB4bPG2RW5b8MRaJA7DdjpKZC/5CeavwAs+Ay3n3k41OKTTfEfJoJKtQQZnCrqnZfq9IVZI26xfYo0cgSYbi8wCie6nqIBdu9k54nqhePPshi22VcFuOh97xxPvY7kiUaRbbKqxn9PFwrYQJBAMsO3uOnYSJxN/FuxksKLqhtNei2GUC/0l7uIE8rbRdtN3QOpcC5suj7id03/IMn2Ks+Vsrmi0lV4VV/c8xyo9UCQQCoKDlObjbYeYYdW7/NvI6cEntgHygENi7b6WFk+dbRhJQgrFH8Z/Idj9a2E3BkfLCTUM1Z/Z3e7D0iqPDKBn/tAkBAHI3bKvnMOhsDq4oIH0rj+rdOplAK1YXCW0TwOjHTd7ROfGFxHDCUxvacVhTwBCCw0JnuriPEH81phTg2kOuRAkAEPR9UrsqLImUTEGEBWqNto7mgbqifko4T1QozdWjI10K0oCNg7W3Y+Os8o7jNj6cTz5GdlxsHp4TS/tczAH7xAkBY6KPIlF1FfiyJAnBC8+jJr2h4TSPQD7sbJJmYw7mvR+f1T4tsWY0aGux69hVm8BoaLStBVPdkaENBMdP+a07u"
		],[
			keyNo: 4,
			public: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQClF0yuCpo3r1ZpYlGcyI5wy5nnvZdOZmxqz5U2rklt2b8+9uWhmsGdpbTv5+qJXlZmvUKbpoaPxpJluBFDJH2GSpq3I0whh0gNq9Arzpp/TDYaZLb6iIqDMF6wm8yjGOtcSkB7qLQWkXpEN9T2NsEzlfTc+GTKc07QXHnzxoLmwQIDAQAB",
			private: "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKUXTK4KmjevVmliUZzIjnDLmee9l05mbGrPlTauSW3Zvz725aGawZ2ltO/n6oleVma9Qpumho/GkmW4EUMkfYZKmrcjTCGHSA2r0CvOmn9MNhpktvqIioMwXrCbzKMY61xKQHuotBaRekQ31PY2wTOV9Nz4ZMpzTtBcefPGgubBAgMBAAECgYB4wCz+05RvDFk45YfqFCtTRyg//0UvO+0qxsBN6Xad2XlvlWjqJeZd53kLTGcYqJ6rsNyKOmgLu2MS8Wn24TbJmPUAwZU+9cvSPxxQ5k6bwjg1RifieIcbTPC5wHDqVy0/Ur7dt+JVMOHFseR/pElDw471LCdwWSuFHAKuiHsaUQJBANHiPdSU3s1bbJYTLaS1tW0UXo7aqgeXuJgqZ2sKsoIEheEAROJ5rW/f2KrFVtvg0ITSM8mgXNlhNBS5OE4nSD0CQQDJXYJxKvdodeRoj+RGTCZGZanAE1naUzSdfcNWx2IMnYUD/3/2eB7ZIyQPBG5fWjc3bGOJKI+gy/14bCwXU7zVAkAdnsE9HBlpf+qOL3y0jxRgpYxGuuNeGPJrPyjDOYpBwSOnwmL2V1e7vyqTxy/f7hVfeU7nuKMB5q7z8cPZe7+9AkEAl7A6aDe+wlE069OhWZdZqeRBmLC7Gi1d0FoBwahW4zvyDM32vltEmbvQGQP0hR33xGeBH7yPXcjtOz75g+UPtQJBAL4gknJ/p+yQm9RJB0oq/g+HriErpIMHwrhNoRY1aOBMJVl4ari1Ch2RQNL9KQW7yrFDv7XiP3z5NwNDKsp/QeU="
		],[
			keyNo: 5,
			public: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChN8Xc+gsSuhcLVM1W1E+e1o+celvKlOmuV6sJEkJecknKFujx9+T4xvyapzyePpTBn0lA9EYbaF7UDYBsDgqSwgt0El3gV+49O56nt1ELbLUJtkYEQPK+6Pu8665UG17leCiaMiFQyoZhD80PXhpjehqDu2900uU/4DzKZ/eywwIDAQAB",
			private: "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKE3xdz6CxK6FwtUzVbUT57Wj5x6W8qU6a5XqwkSQl5yScoW6PH35PjG/JqnPJ4+lMGfSUD0RhtoXtQNgGwOCpLCC3QSXeBX7j07nqe3UQtstQm2RgRA8r7o+7zrrlQbXuV4KJoyIVDKhmEPzQ9eGmN6GoO7b3TS5T/gPMpn97LDAgMBAAECgYAy+uQCwL8HqPjoiGR2dKTI4aiAHuEv6m8KxoY7VB7QputWkHARNAaf9KykawXsNHXt1GThuV0CBbsW6z4U7UvCJEZEpv7qJiGX8UWgEs1ISatqXmiIMVosIJJvoFw/rAoScadCYyicskjwDFBVNU53EAUD3WzwEq+dRYDn52lqQQJBAMu30FEReAHTAKE/hvjAeBUyWjg7E4/lnYvb/i9Wuc+MTH0q3JxFGGMb3n6APT9+kbGE0rinM/GEXtpny+5y3asCQQDKl7eNq0NdIEBGAdKerX4O+nVDZ7PXz1kQ2ca0r1tXtY/9sBDDoKHP2fQAH/xlOLIhLaH1rabSEJYNUM0ohHdJAkBYZqhwNWtlJ0ITtvSEB0lUsWfzFLe1bseCBHH16uVwygn7GtlmupkNkO9o548seWkRpnimhnAE8xMSJY6aJ6BHAkEAuSFLKrqGJGOEWHTx8u63cxiMb7wkK+HekfdwDUzxO4U+v6RUrW/sbfPNdQ/FpPnaTVdV2RuGhg+CD0j3MT9bgQJARH86hfxp1bkyc7f1iJQT8sofdqqVz5grCV5XeGY77BNmCvTOGLfL5pOJdgALuOoP4t3e94nRYdlW6LqIVugRBQ=="
		]
	]
}

def getSmartLanData(response) {
	logDebug("getSmartLanData: responses returned from devices")
	def devIp
	List ipList = []
	def respData
	if (response instanceof Map) {
		devIp = getDeviceIp(response)
		if (devIp != "INVALID") {
			ipList << devIp
		}
	} else {
		response.each {
			devIp = getDeviceIp(it)
			if (devIp != "INVALID") {
				ipList << devIp
			}
			pauseExecution(100)
		}
	}
	getAllSmartDeviceData(ipList)
}

def getDeviceIp(response) {
	log.trace response
	def brand = "KASA"
	if (APP_NAME == "tapo_device_install") { brand = "TAPO" }
	def devIp = "INVALID"
	try {
		def respData = parseLanMessage(response.description)
		if (respData.type == "LAN_TYPE_UDPCLIENT") {
			byte[] payloadByte = hubitat.helper.HexUtils.hexStringToByteArray(respData.payload.drop(32))
			String payloadString = new String(payloadByte)
			Map payload = new JsonSlurper().parseText(payloadString).result
			Map payloadData = [type: payload.device_type, model: payload.device_model,
							   mac: payload.mac, ip: payload.ip]
			if (payload.device_type.contains(brand)) {
				devIp = payload.ip
				logInfo("getDeviceIp: [TAPOdevice: ${payloadData}]")
			} else {
				logInfo("getDeviceIp: [KASAdevice: ${payloadData}]")
			}
		}
	} catch (err) {
		logWarn("getDevIp: [status: ERROR, respData: ${resData}, error: ${err}]")
	}
	return devIp
}

def getAllSmartDeviceData(List ipList) {
	Map logData = [:]
	ipList.each { devIp ->
		Map devData = [:]
		def cmdResp = getSmartDeviceData([method: "get_device_info"], devIp)
		if (cmdResp == "ERROR") {
			devData << [status: "ERROR", data: "Failure in getSmartDeviceData"]
		} else {
			if (cmdResp.result.type.contains("SMART")) {
				devData << [status: "OK"]
				parseSmartDeviceData(cmdResp.result)
			} else {
				if (cmdResp.result.type) {
					devData << [status: "OK", devType: cmdResp.result.type, devIp: cmdResp.result.ip]
				} else {
					devData << [status: "ERROR", data: cmdResp]
				}
			}
		}
		logData << [devIp: devData]
		pauseExecution(200)
	}
	if (!logData.toString().contains("ERROR")) {
		logDebug("getSmartDeviceData: ${logData}")
	} else {
		logWarn("getSmartDeviceData: ${logData}")
	}
	pauseExecution(5000)
	state.findingDevices = "done"
}

def deviceLogin(devIp) {
	Map logData = [:]
	def handshakeData = handshake(devIp)
	if (handshakeData.respStatus == "OK") {
		Map credentials = [encUsername: encUsername, encPassword: encPassword]
		def tokenData = loginDevice(handshakeData.cookie, handshakeData.aesKey,
									credentials, devIp)
		if (tokenData.respStatus == "OK") {
			logData << [rsaKeys: handshakeData.rsaKeys,
						cookie: handshakeData.cookie,
						aesKey: handshakeData.aesKey,
						token: tokenData.token]
		} else {
			logData << [tokenData: tokenData]
		}
	} else {
		logData << [handshakeData: handshakeData]
	}
	return logData
}

def getSmartDeviceData(cmdBody, devIp) {
	def cmdResp = "ERROR"
	def loginData = deviceLogin(devIp)
	Map logData = [cmdBody: cmdBody, devIp: devIp, token: loginData.token, aeskey: loginData.aesKey, cookie: loginData.cookie]
	if (loginData.token == null) {
		logData << [respStatus: "FAILED", reason: "Check Credentials"]
	} else {
		def uri = "http://${devIp}/app?token=${loginData.token}"
		cmdBody = JsonOutput.toJson(cmdBody).toString()
		Map reqBody = [method: "securePassthrough",
					   params: [request: encrypt(cmdBody, loginData.aesKey)]]
		def respData = syncPost(uri, reqBody, loginData.cookie)
		if (respData.status == "OK") {
			logData << [respStatus: "OK"]
			respData = respData.resp.data.result.response
			cmdResp = new JsonSlurper().parseText(decrypt(respData, loginData.aesKey))
		} else {
			logData << respData
		}
	}
	if (logData.respStatus == "OK") {
		logDebug("getSmartDeviceData: ${logData}")
	} else {
		logWarn("getSmartDeviceData: ${logData}")
	}
	return cmdResp
}

def debugOff() { app.updateSetting("debugLog", false) }
def logTrace(msg) { log.trace "kasa-${VERSION}: ${msg}" }
def logDebug(msg){
	if(debugLog == true) { log.debug "kasa-${VERSION}: ${msg}" }
}
def logInfo(msg) { log.info "kasa-${VERSION}: ${msg}" }
def logWarn(msg) { log.warn "kasa-${VERSION}: ${msg}" }
