import groovy.json.JsonBuilder
import groovy.transform.Field
import hubitat.helper.HexUtils
import hubitat.matter.DataType
import java.lang.Math
import java.util.concurrent.*
import org.apache.commons.lang3.StringUtils

metadata {
    definition(name: 'Matter LAN Device', namespace: 'matter', author: 'Dan Abdinoor',
               importUrl: 'https://raw.githubusercontent.com/abdinoor/Hubitat/refs/heads/master/matter-lan-driver.groovy') {
        capability "Switch"
        capability "Refresh"
        capability "Switch Level"
    }

    preferences {
        section {
            input name: 'logEnable',
                    type: 'bool',
                    title: 'Enable debug logging',
                    required: false,
                    defaultValue: false

            input name: 'txtEnable',
                    type: 'bool',
                    title: 'Enable descriptionText logging',
                    required: false,
                    defaultValue: true

            input name: 'pollRefresh',
                    title: 'Polling Refresh in Seconds',
                    type: 'number',
                    required: true,
                    defaultValue: '300'
        }
    }
}


/* -------------------------------------------------------
 * Hubitat commands
 */

def installed() {
    def instStatus = installCommon()
    state.remove("flashing")
    state.remove("bin")
    device.updateSetting("txtEnable",[type:"bool",value:true])
    device.updateSetting("logEnable",[type:"bool",value:false])
    logInfo("installed: ${instStatus}")
    refresh()
}

/* called when device settings are saved */
def updated() {
    refresh()
    def updStatus = [:]

    updateDataValue("pollRefresh", pollRefresh.toString())
    updStatus << [pollRefresh: pollRefresh]
    runIn(getRefreshSeconds(), poll)

    LOG.debug "updated: ${updStatus}"

}

// on implements Matter 1.2 Cluster Spec Section 1.5.7.2, On command
void on(){
    try {
        Map inputs = [ ep: getEndpoint(device)]
        assert inputs.ep instanceof Integer // Use Integer, not Hex!
        sendHubCommand(new hubitat.device.HubAction(matter.invoke(inputs.ep, 0x0006, 0x01 ), hubitat.device.Protocol.MATTER))
        sendEvent(name: "switch", value: "on")
    } catch (AssertionError e) {
        LOG.error "Incorrect parameter type or value used in on() method.<br><pre>${e}<br><br>Stack trace:<br>${getStackTrace(e) }"
    } catch(e){
        LOG.error "<pre>${e}<br><br>when processing on with inputs ${inputs}<br><br>Stack trace:<br>${getStackTrace(e) }"
    }
}

// off implements Matter 1.2 Cluster Spec Section 1.5.7.1, Off command
void off(){
    try {
        Map inputs = [ ep: getEndpoint(device) ]
        assert inputs.ep instanceof Integer  // Use Integer, not Hex!
        sendHubCommand(new hubitat.device.HubAction(matter.invoke(inputs.ep, 0x0006, 0x00), hubitat.device.Protocol.MATTER))
        sendEvent(name: "switch", value: "off")
    } catch (AssertionError e) {
        LOG.error "Incorrect parameter type or value used in off() method.<br><pre>${e}<br><br>Stack trace:<br>${getStackTrace(e) }"
    } catch(e){
        LOG.error "<pre>${e}<br><br>when processing off with inputs ${inputs}<br><br>Stack trace:<br>${getStackTrace(e) }"
    }
}

void setLevel(level, ramp = null, onTime = null ) {
    setLevel(ep: getEndpoint(),
             level: level as Integer,
             transitionTime10ths: ramp.is(null) ? 0 : (ramp * 10) as Integer
    )
}

void setLevel( Map params = [:] ) {
    try {
        Map inputs = [ep: null , level: null , transitionTime10ths: null ] << params
        assert inputs.ep instanceof Integer  // Check that endpoint is an integer
        if (inputs.level instanceof BigDecimal) inputs.level = inputs.level as Integer // Web UI send BigDecimal but want Integer! Fix that.
        assert inputs.level instanceof Integer
        inputs.level = Math.round(Math.max(Math.min(inputs.level, 100), 0)) // level is a % and must be between 0 and 100

        assert inputs.transitionTime10ths instanceof Integer

        String hexLevel = HexUtils.integerToHexString((Integer) ( inputs.level  * 2.54), 1)
        String hexTransitionTime10ths = HexUtils.integerToHexString(inputs.transitionTime10ths, 2 ) // Time is in 10ths of a second! FFFF is the null value.

        List<Map<String, String>> fields = []
        fields.add(matter.cmdField(DataType.UINT8, 0, hexLevel)) // Level
        fields.add(matter.cmdField(DataType.UINT16, 1, (hexTransitionTime10ths[2..3] + hexTransitionTime10ths[0..1]) )) // TransitionTime in 0.1 seconds, uint16 0-65534, byte swapped
        fields.add(matter.cmdField(DataType.UINT8,  2, "00")) // OptionMask, map8
        fields.add(matter.cmdField(DataType.UINT8,  3, "00"))  // OptionsOverride, map8
        LOG.debug "fields are ${fields}"
        String cmd = matter.invoke(inputs.ep, 0x0008, 0x04, fields) // Move To Level with On/Off
        LOG.debug "sending command with transitionTime10ths value ${inputs.transitionTime10ths}: ${cmd}"

        sendHubCommand(new hubitat.device.HubAction(cmd, hubitat.device.Protocol.MATTER))
        sendEvent(name: "level", value: inputs.level)
        sendEvent(name: "switch", value: inputs.level ? "on" : "off")
    } catch (AssertionError e) {
        LOG.error "Incorrect parameter type or value used in setLevel() method.<br><pre>${e}<br><br>Stack trace:<br>${getStackTrace(e) }"
    } catch(e){
        LOG.error "<pre>${e}<br><br>when processing setLevel with inputs ${inputs}<br><br>Stack trace:<br>${getStackTrace(e) }"
    }
}

void refresh() {
    refreshMatter(ep: getEndpoint())
}

// Performs a refresh on a designated endpoint / cluster / attribute (all specified in Integer)
// Does a wildcard refresh if parameters are not specified (ep=FFFF / cluster=FFFFFFFF/ endpoint=FFFFFFFF is the Matter wildcard designation
void refreshMatter(Map params = [:]) {
    try {
        Map inputs = [ep:0xFFFF, clusterInt: 0xFFFFFFFF, attrInt: 0xFFFFFFFF] << params
        assert inputs.ep instanceof Integer         // Make sure the type is as expected!
        assert inputs.clusterInt instanceof Integer || inputs.clusterInt instanceof Long
        assert inputs.attrInt instanceof Integer || inputs.attrInt instanceof Long

        String cmd = $/he rattrs [{"ep":"${inputs.ep}","cluster":"${inputs.clusterInt}","attr":"${inputs.attrInt}"}]/$
        sendHubCommand(new hubitat.device.HubAction(cmd, hubitat.device.Protocol.MATTER))
    } catch (AssertionError e) {
        LOG.error "Incorrect parameter type or value used in refreshMatter method.<br><pre>${e}<br><br>Stack trace:<br>${getStackTrace(e) }"
    } catch(e){
        LOG.error "<pre>${e}<br><br>when processing refreshMatter with inputs ${inputs}<br><br>Stack trace:<br>${getStackTrace(e) }"
    }
}

def poll() {
    runIn(getRefreshSeconds(), poll)
    refresh()
}


def sendCmd(int command, String payload) {
    int seqno = 1
    if (state.seqno != null) {
        seqno = state.seqno++
    }
    state.lastCommand = payload
    sendLanCmd(seqno, command, payload)
}

/* get refresh rate or a default */
def getRefreshSeconds() {
    def seconds = getDataValue("pollRefresh")
    if (seconds == null) return 300
    return Integer.parseInt(getDataValue("pollRefresh"))
}


/* -------------------------------------------------------
 * Communication methods
 */

// This parser handles the Matter event message originating from Hubitat.
void parse(String description) {
    Map decodedDescMap = parseDescriptionAsDecodedMap(description) // Using parser from matterTools.parseDescriptionAsDecodedMap

    // Following code stores received cluster values in case you want to use them elsewhere
    // But many clusters just aren't needed elsewhere!
    List<Integer> ignoreTheseClusters = [0x001F, // Access Control
                                         0x0029, // OTA Provider Cluster
                                         0x002A, // OTA Software Update Requestor
                                         0x002B, // Localization
                                         0x002C, // Time Format
                                         0x002D, // Unit Localization
                                         0x002E, // Power Source Configuration - but Power Source Cluster, 0x002F is processed!
                                         0x0030, // General Commissioning
                                         0x0031, // Network Commissioning
                                         0x0032, // Diagnostics Log
                                         0x0033, // General Diagnostics. Has some interesting stuff here, like the IP addresses. Consider using later!
                                         0x0034, // Software Diagnostics
                                         0x0035, // Thread Diagnostics. Events have been implemented, but this produces a lot of activity
                                         0x0036, // WiFi Diagnostics. Events have been implemented, but this produces a lot of activity
                                         0x0037, // Ethernet Diagnostics
                                         0x0038, // Time Sync Cluster
                                         0x003C, // Administrative Commissioning
                                         0x003E, // Node Operational Credentials
                                         0x003F, // Group Key Management
                                        ]

    List<Integer> ignoreTheseAttributes = [0xFFF8,// GeneratedCommandList
                                           0xFFF9, // AceptedCommandList
                                           0xFFFA, // EventList
                                           0xFFFB, // Attribute List
                                           0xFFFD, // ClusterRevision
                                           0xFE, // Fabric Index
                                          ]
    LOG.debug "In parse, Matter attribute report string:<br><font color = 'green'>${description}<br><font color = 'black'>was decoded as: <font color='blue'>${decodedDescMap}"

    if ((decodedDescMap.clusterInt in ignoreTheseClusters) || (decodedDescMap.attrInt in ignoreTheseAttributes)) {
        return
    }

    storeRetrievedData(decodedDescMap)

    List<Map> hubEvents = getHubitatEvents(decodedDescMap)
    if (hubEvents.is(null)) {
        return
    }

    LOG.debug "Events generated: <font color='blue'>${hubEvents}"

    try {
        parse(hubEvents)
    } catch(e) {
        LOG.error "<pre>parse: ${e}<br><br>when processing description string ${description}<br><br>Stack trace:<br>${getStackTrace(e) }"
    }
}


// This parse routine handles Hubitat SendEvent type messages (not the description raw strings originating from the device).
// Hubitat's convention is to include a parse() routine with this function in Generic Component drivers (child device drivers).
// It accepts a List of one or more SendEvent-type Maps and operates to determine how those Hubitat sendEvent Maps should be handled.
// The List of SendEvent Maps may include event Maps that are not needed by a particular driver (as determined based on the attributes of the driver)
// and those "extra" Maps are discarded. This allows a more generic "event Map" producting method (e.g., matterTools.createListOfMatterSendEventMaps)
void parse(List sendEventTypeOfEvents) {
    LOG.debug "${description}"
        List updateLocalStateOnlyAttributes = ["OnOffTransitionTime", "OnTransitionTime", "OffTransitionTime", "MinLevel", "MaxLevel",
                                               "DefaultMoveRate", "OffWaitTime", "Binding", "UserLabelList", "FixedLabelList", "VisibleIndicator",
                                               "DeviceTypeList", "ServerList", "ClientList", "PartsList", "TagList"]
        sendEventTypeOfEvents.each {
            if (device.hasAttribute (it.name)) {
                if (txtEnable) {
                    if(device.currentValue(it.name) == it.value) {
                        LOG.desc ((it.descriptionText) ? (it.descriptionText) : ("${it.name} set to ${it.value}") )+" (unchanged)"
                    } else {
                        LOG.desc ((it.descriptionText) ? (it.descriptionText) : ("${it.name} set to ${it.value}") )
                    }
                }
                sendEvent(it)
            } else if (updateLocalStateOnlyAttributes.contains(it.name)) {
                device.updateDataValue(it.name, "${it.value}")
            }
        }
        // LOG.error "<pre>${e}<br><br>when processing parse with inputs ${sendEventTypeOfEvents}<br><br>Stack trace:<br>${getStackTrace(e) }"
}

Integer getEndpoint() {
    return getEndpoint(device)
}

Integer getEndpoint(com.hubitat.app.DeviceWrapper thisDevice) {
    //device.getDataValue("endpointId").is(null) ? 1 : Integer.parseInt(device.getDataValue("endpointId"))

    String rValue =  thisDevice?.getDataValue("endpointId") ?: thisDevice?.endpointId
    if (rValue.is( null )) {
        LOG.error "device does not have a defined endpointId"
        return 1
    }
    return Integer.parseInt(rValue, 16)
}

// Per Matter Spec Appendix A.6, values greater than 0b11000 are reserved, except for 0b00011000 which is End-of-Container
Boolean isReservedValue(Integer controlOctet){
    return  ( ((controlOctet & 0b00011111) >= (0b11000)) && !(controlOctet == 0b00011111))
}

String HexToString(String hexStr){
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    for (int i = 0; i < hexStr.length(); i += 2) {
      baos.write(Integer.parseInt(hexStr.substring(i, i + 2), 16));
    }
    return baos.toString()
    // return new String(baos.toByteArray() );
}

// Strings are immutable in groovy, but StringBuilder strings are not.
// Since the valueString is changed within the function, it needs to be passed as a StringBuilder type string.
Object getTagValue(StringBuilder valueString, Integer tagControl){
    Object rValue
    switch(tagControl){
        case 0b000: // 0 Octets
            rValue = null; break;
        case 0b001: // Context-specific, 1 octet
            rValue = Integer.parseInt(valueString[0..1] , 16); valueString.delete(0,2); break
        case 0b010: // Common Profile, 2 octets. Not really sure how this should be represented. For now, using a string!
            rValue = valueString[0..3]; valueString.delete(0,4);  break
        case 0b011: // Common Profile, 4 octets. Not really sure how this should be represented. For now, using a string!
            rValue = valueString[0..7]; valueString.delete(0,8); break
        case 0b100: // Implicit Profile, 2 octets. Not really sure how this should be represented. For now, using a string!
            rValue = valueString[0..3]; valueString.delete(0,4); break
        case 0b101: // Implicit Profile, 4 octets. Not really sure how this should be represented. For now, using a string!
            rValue = valueString[0..7]; valueString.delete(0,8); break
        case 0b110: // Fully-Qualified form, 6 octets. Not really sure how this should be represented. For now, using a string!
            rValue = valueString[0..11];  valueString.delete(0,12); break
        case 0b111: // Fully-Qualified form, 8 octets. Not really sure how this should be represented. For now, using a string!
            rValue = valueString[0..15];  valueString.delete(0, 16); break
    }
    return rValue
}

// Strings are immutable in groovy, but StringBuilder strings are not.
// Since the valueString is changed within the function, it needs to be passed as a StringBuilder type string
Object getElementValue(StringBuilder valueString, Integer elementType){
    Object rValue = null
    try {
        switch(elementType){
        case 0b00000: // Signed Integer, 1-Octet
            assert valueString.length() >= 2 // If this fails, length is too short. Raise an assertion error!
            rValue = Integer.parseInt(byteReverseParameters(valueString[0..1]), 16) // Parse the next octet
            if(rValue & 0x80) rValue = rValue - 256 // Make into a negative if greater than 0x80
            valueString = valueString.delete(0, 2) // Trim valueString to remove the octets that were just processed
            break;
        case 0b00001: // Signed Integer, 2-Octet
            assert valueString.length() >= 4 // If this fails, length is too short. Raise an assertion error!
            rValue = Integer.parseInt(byteReverseParameters(valueString[0..3]), 16) // Parse the next 2 octets
            if(rValue & 0x8000) rValue = rValue - 65536 // Make into a negative if greater than 0x8000
            valueString = valueString.delete(0, 4) // Trim valueString to remove the octets that were just processed
            break;
        case 0b00010: // Signed Integer, 4-Octet
            assert valueString.length() >= 8 // If this fails, length is too short. Raise an assertion error!
            rValue = Long.parseLong(byteReverseParameters(valueString[0..7]), 16) as Integer // Parse the next 4 octets. Need to parse as Long then change to Integer or can get a numeric exception on negative numbers (odd!)
            // if(rValue & 0x8000_0000) rValue = rValue - 0xFFFF_FFFF -1 // Make into a negative if greater than 0x8000_0000
            valueString = valueString.delete(0, 8) // Trim valueString to remove the octets that were just processed
            break;
        case 0b00011: // Signed Integer, 8-Octet
            assert valueString.length() >= 16 // If this fails, length is too short. Raise an assertion error!
            rValue = (new BigInteger(byteReverseParameters(valueString[0..15]), 16)) as Long // Parse the next 8 octets then change to long.
            valueString = valueString.delete(0, 16) // Trim valueString to remove the octets that were just processed
            return rValue
            break;

        case 0b00100: // Unsigned Integer, 1-Octet
            assert valueString.length() >= 2 // If this fails, length is too short. Raise an assertion error!
            rValue = Integer.parseInt(byteReverseParameters(valueString[0..1]), 16) // Parse the next octet
            valueString = valueString.delete(0, 2) // Trim valueString to remove the octets that were just processed
            break;
        case 0b00101: // Unsigned Integer, 2-Octet
            assert valueString.length() >= 4 // If this fails, length is too short. Raise an assertion error!
            rValue = Integer.parseInt(byteReverseParameters(valueString[0..3]), 16) // Parse the next 2 octets
            valueString = valueString.delete(0, 4) // Trim valueString to remove the octets that were just processed
            break;
        case 0b00110: // Unsigned Integer, 4-Octet - Need to return as an 8 Octet Long, since normal 4 Octet Integer can't fit all unsigned values!
            assert valueString.length() >= 8 // If this fails, length is too short. Raise an assertion error!
            rValue = Long.parseLong(byteReverseParameters(valueString[0..7]), 16) // Parse the next 4 octets
            valueString = valueString.delete(0, 8) // Trim valueString to remove the octets that were just processed
            break;
        case 0b00111: // Unsigned Integer, 8-Octet - Need to return as an 8 Octet Long, since normal 4 Octet Integer can't fit all unsigned values!
            assert valueString.length() >= 16 // If this fails, length is too short. Raise an assertion error!
            rValue = (new BigInteger(byteReverseParameters(valueString[0..15]), 16)) // Parse the next 8 octets as BigInteger.
            valueString = valueString.delete(0, 16) // Trim valueString to remove the octets that were just processed
            break;

        case 0b01000: // Boolean False
            rValue = false;
            break;
            case 0b01001: // Boolean True
            rValue = true;
            break;

        case 0b01010: // Floating Point, 4-Octet Value
            assert valueString.length() >= 8 // If this fails, length is too short. Raise an assertion error!
            rValue = Float.intBitsToFloat(Integer.parseInt(byteReverseParameters(valueString[0..7]), 16)) // Parse the next 4 octets
            valueString = valueString.delete(0, 8) // Trim valueString to remove the octets that were just processed
            break;
        case 0b01011: // Floating Point, 8-Octet Value
            assert valueString.length() >= 16 // If this fails, length is too short. Raise an assertion error!
            rValue = Double.longBitsToDouble(Long.parseLong(byteReverseParameters(valueString[0..15]), 16)) // Parse the next 8 octets
            valueString = valueString.delete(0, 16) // Trim valueString to remove the octets that were just processed
            break;

        case 0b01100: // UTF-8 String, 1-octet length
            Integer length = Integer.parseInt(byteReverseParameters(valueString[0..1]), 16)
            valueString = valueString.delete(0, 2)
            if (length == 0) { rValue = ""; break }
            rValue = HexToString(valueString[0..(length*2-1)])
            valueString = valueString.delete(0, (length*2))
            break;
        case 0b01101: // UTF-8 String, 2-octet length
            Integer length = Integer.parseInt(byteReverseParameters(valueString[0..3]), 16)
            valueString = valueString.delete(0, 4)
            if (length == 0) { rValue = ""; break }
            rValue = HexToString(valueString[0..(length*2-1)])
            valueString = valueString.delete(0, (length*2))
            break;
        case 0b01110: // UTF-8 String, 4-octet length
            Integer length = Integer.parseInt(byteReverseParameters(valueString[0..7]), 16)
            valueString = valueString.delete(0, 8)
            if (length == 0) { rValue = ""; break }
            rValue = HexToString(valueString[0..(length*2-1)])
            valueString = valueString.delete(0, (length*2))
            break;
        case 0b01111: // UTF-8 String, 8-octet length
            Long length = Long.parseLong(byteReverseParameters(valueString[0..15]), 16)
            valueString = valueString.delete(0, 16)
            if (length == 0) { rValue = ""; break }
            rValue = HexToString(valueString[0..((int)length*2-1)])
            valueString = valueString.delete(0, ((int)length*2))
            break;

        case 0b10000: // Octet String, 1-octet length
            Integer length = Integer.parseInt(byteReverseParameters(valueString[0..1]), 16)
            valueString = valueString.delete(0, 2)
            rValue = new byte[length]
            for(i = 0; i<length; i++) {
             rValue[i] = Integer.parseInt(valueString[(i*2)..(i*2+1)], 16) as Byte
            }
            valueString = valueString.delete(0, ((int)length*2))
            break;
        case 0b10001: // Octet String, 2-octet length
            Integer length = Integer.parseInt(byteReverseParameters(valueString[0..3]), 16)
            valueString = valueString.delete(0, 4)
            rValue = new byte[length]
            for(i = 0; i<length; i++) {
             rValue[i] = Integer.parseInt(valueString[(i*2)..(i*2+1)], 16) as Byte
            }
            valueString = valueString.delete(0, ((int)length*2))
            break;
        case 0b10010: // Octet String, 4-octet length
            Integer length = Integer.parseInt(byteReverseParameters(valueString[0..7]), 16)
            valueString = valueString.delete(0, 8)
            rValue = new byte[length]
            for(i = 0; i<length; i++) {
             rValue[i] = Integer.parseInt(valueString[(i*2)..(i*2+1)], 16) as Byte
            }
            valueString = valueString.delete(0, ((int)length*2))
            break;
        case 0b10011: // Octet String, 8-octet length
            Long length = Long.parseLong(byteReverseParameters(valueString[0..15]), 16)
            valueString = valueString.delete(0, 16)
            rValue = new byte[length]
            for(i = 0; i<length; i++) {
             rValue[i] = Integer.parseInt(valueString[(i*2)..(i*2+1)], 16) as Byte
            }
            valueString = valueString.delete(0, ((int)length*2))
            break;

        case 0b10100: // Null
            rValue = null;
            break;

        case 0b10101: // Structure
             rValue = []

            // Now add each sub-element to the structure. Maximum 100 times through the loop!
            for(int i = 0; (Integer.parseInt(valueString[0..1], 16) != 0b00011000) && (i<100); i++) { // IF the next Octet is not the End-Of-Container
                // Recursively process the contents and push into the map rValue
                rValue << parseToValue(valueString)
            }
            valueString = valueString.delete(0,2) // Reached End-Of-Container, so trim that off!
            if(rValue.every{it instanceof Map}){
                 rValue = rValue.collectEntries({ it })
            }
            break;
        case 0b10110: // Array
            rValue = []
            // Now add each sub-element to the Array. Maximum 100 times through the loop!
            for(int i = 0; (Integer.parseInt(valueString[0..1], 16) != 0b00011000) && (i<100); i++) { // IF the next Octet is not the End-Of-Container
                // Recursively process the contents and push into the map rValue
                rValue << parseToValue(valueString)
            }
            valueString = valueString.delete(0,2) // Reached End-Of-Container, so trim that off!
            break;
        case 0b10111: // List
            rValue = []
            // Now add each sub-element to the List. Maximum 100 times through the loop!
            for(int i = 0; (Integer.parseInt(valueString[0..1], 16) != 0b00011000) && (i<100); i++) { // IF the next Octet is not the End-Of-Container
            // Recursively process the contents and push into the map rValue
            rValue << parseToValue(valueString)
            }
            valueString = valueString.delete(0,2) // Reached End-Of-Container, so trim that off!
            break;
        case 0b00011000: // End of container
            LOG.error "end-of-container encountered. Should have been caught in the struture, list, or array processing loop. What happened?"
            break;
        case 0b11001: // Reserved
        case 0b11010: // Reserved
        case 0b11011: // Reserved
        case 0b11100: // Reserved
        case 0b11101: // Reserved
        case 0b11110: // Reserved
        case 0b11111: // Reserved
            LOG.error "Received a Reserved value - Whaaaat?"; break
            rValue= null
            break;
        }
        return rValue
    } catch(AssertionError e)  {
        LOG.error "In method parseDescriptionAsDecodedMap, Assertion failed with <pre>${e}"
        return null
    }catch(e) {
        LOG.error "In method parseDescriptionAsDecodedMap, error is <pre>${e}"
        return null
    }
}

// This parser handles the Matter event message originating from Hubitat.
// valueString is the string description.value originally passed to the driver's parse(description) method from Hubitat
Object parseToValue(StringBuilder valueString) {
    if(valueString?.length() < 2) return null
    Integer controlOctet = Integer.parseInt(valueString[0..1], 16)
    assert !(isReservedValue(controlOctet)) // Should never get a reserved value!
    Integer elementType = controlOctet & 0b00011111
    Integer tagControl  = (controlOctet & 0b11100000) >> 5
    valueString.delete(0,2) // Delete the control octet since its been convereted to tagControl and ElementType
    Object tag = getTagValue(valueString, tagControl)
    Object element = getElementValue(valueString, elementType)
    return (tag.is(null)) ? (element) : [(tag):(element)]
}

Map parseRattrDescription(description){
    assert (description[0..8] == "read attr")
    return description.substring( description.indexOf("-") +1).split(",")
                        .collectEntries{ entry -> def pair = entry.split(":");
                            [(pair.first().trim()):(pair.last().trim())]
                        }
}

Map parseDescriptionAsDecodedMap(description){
    try {
        Map rattrKeyValues = parseRattrDescription(description)
        Map rValue = [:]
        rValue.put( ("clusterInt"),  Integer.parseInt(rattrKeyValues.cluster, 16) )
        rValue.put( ("attrInt"),     Integer.parseInt(rattrKeyValues.attrId, 16) )
        rValue.put( ("endpointInt"), Integer.parseInt(rattrKeyValues.endpoint, 16) )

        StringBuilder parseRattrString = new StringBuilder(rattrKeyValues.value)
        Object decodedValue = parseToValue(parseRattrString)
        rValue.put("decodedValue", decodedValue)
        return rValue
    } catch(AssertionError e)  {
        LOG.error "In method parseDescriptionAsDecodedMap, Assertion failed with <pre>${e}"
    } catch(e) {
        LOG.error "In method parseDescriptionAsDecodedMap, error is <pre>${e}"
    }
}

// Matter payloads need hex parameters of greater than 2 characters to be pair-reversed.
// This function takes a list of parameters and pair-reverses those longer than 2 characters.
// Alternatively, it can take a string and pair-revers that.
// Thus, e.g., ["0123", "456789", "10"] becomes "230189674510" and "123456" becomes "563412"
private String byteReverseParameters(String oneString) { byteReverseParameters([] << oneString) }
private String byteReverseParameters(List<String> parameters) {
    StringBuilder rStr = new StringBuilder(64)
    for (hexString in parameters) {
        if (hexString.length() % 2) throw new Exception("In method byteReverseParameters, trying to reverse a hex string that is not an even number of characters in length. Error in Hex String: ${hexString}, All method parameters were ${parameters}.")

        for(Integer i = hexString.length() -1 ; i > 0 ; i -= 2) {
            rStr << hexString[i-1..i]
        }
    }
    return rStr
}

void writeClusterAttribute(clusterId, attributeId, hexValue, dataType) {
    writeClusterAttribute(
            ep: null,
            clusterInt: Integer.parseInt( clusterId, 16),
            attributeInt: Integer.parseInt( attributeId, 16),
            hexValue:hexValue,
            hubitatDataType: dataType
    )
}
void writeClusterAttribute(Map params = [:]) {
    try {
        Map inputs = [ep: null, clusterInt: null , attributeInt: null , hexValue: null] << params
        assert inputs.ep instanceof Integer
        assert inputs.clusterInt instanceof Integer
        assert inputs.attributeInt instanceof Integer

        List<Map<String, String>> attrWriteRequests = []
            attrWriteRequests.add(matter.attributeWriteRequest(inputs.ep, inputs.clusterInt, inputs.attributeInt, getHubitatDataType(*:inputs), inputs.hexValue))
        String cmd = matter.writeAttributes(attrWriteRequests)

        sendHubCommand(new hubitat.device.HubAction(cmd, hubitat.device.Protocol.MATTER))
    } catch (AssertionError e) {
        LOG.error "<pre>${e}<br><br>Stack trace:<br>${getStackTrace(e) }"
    } catch(e){
        LOG.error "<pre>${e}<br><br>when processing writeClusterAttribute with inputs ${inputs}<br><br>Stack trace:<br>${getStackTrace(e) }"
    }
}

void readClusterAttribute(clusterId, attributeId) {
    readClusterAttribute(clusterId:clusterId, attributeId:attributeId)
}

void readClusterAttribute(Map params = [:]) {
    try {
        Map inputs = [ep:null, clusterInt:null, attributeInt:null ] << params
        assert inputs.ep instanceof Integer
        assert inputs.clusterInt instanceof Integer || instance.clusterInt instanceof Long
        assert inputs.attributeInt instanceof Integer || instance.attributeInt instanceof Long

        List<Map<String, String>> attributePaths = []
        attributePaths.add(matter.attributePath(inputs.ep, inputs.clusterInt, inputs.attributeInt))

        String cmd = matter.readAttributes(attributePaths)

        sendHubCommand(new hubitat.device.HubAction(cmd, hubitat.device.Protocol.MATTER))
    } catch (AssertionError e) {
        LOG.error "<pre>${e}<br><br>Stack trace:<br>${getStackTrace(e) }"
    } catch(e){
        LOG.error "<pre>${e}<br><br>when processing readClusterAttribute with inputs ${inputs}<br><br>Stack trace:<br>${getStackTrace(e) }"
    }
}

// Stores attribute values in nested ConcurrentHashMaps. Because this code retrieves many attributes at once, use ConcurrentHashMaps to ensure thread safety.
void storeRetrievedData(Map descMap){
    String netId = device?.getDeviceNetworkId()

    def decodedValue = descMap.decodedValue ? descMap.decodedValue : ""
    globalDataStorage.get(netId, new ConcurrentHashMap<String,ConcurrentHashMap>(8, 0.75, 1))
        .get(descMap.endpointInt, new ConcurrentHashMap<String,ConcurrentHashMap>(8, 0.75, 1))
            .get(descMap.clusterInt, new ConcurrentHashMap<String,ConcurrentHashMap>(8, 0.75, 1))
                .put(descMap.attrInt, decodedValue)
}

// Retrieves a particular attribute from those previously received.
Object getStoredAttributeData(Map params = [:]){
    Map inputs = [endpoint:null, cluster:null, attrId:null] << params
    try {
        assert inputs.keySet().containsAll(userInputs.keySet()) // check that all keys in userInputs are found in the inputs map, meaning the function was called with expected inputs.
        assert inputs.endpoint instanceof String && inputs.endpoint.matches("[0-9A-F]+") // String must be a hex value.
        assert inputs.cluster instanceof String  && inputs.cluster.matches("[0-9A-F]+")  // String must be a hex value.
        assert inputs.attrId instanceof String   && inputs.attrId.matches("[0-9A-F]+")   // String must be a hex value.
    } catch(AssertionError e) {
            LOG.error "<pre>${e}"
            throw(e)
    }

    String netId = device?.getDeviceNetworkId()

    globalDataStorage.get(netId, new ConcurrentHashMap<String,ConcurrentHashMap>(8, 0.75, 1))
        ?.get(descMap.endpoint)
            ?.get(descMap.cluster)
                ?.get(descMap.attrId)

}

void showStoredAttributeData(){
    String netId = device?.getDeviceNetworkId()
    LOG.info "<pre> ${new JsonBuilder(globalDataStorage.get(netId)).toPrettyString()}"
}

void unsubscribeAll(){
    String cmd = matter.unsubscribe()
    LOG.info "Sending command to Unsubscribe from all attribute reports: " + cmd
    sendHubCommand(new hubitat.device.HubAction(cmd, hubitat.device.Protocol.MATTER))
}

void subscribeAll(){
    // This is a wildcard subscribe. Subscribes to all endpoints, all clusters, all attributes
    String cmd = 'subscribe 0x00 0xFF [{"ep":"0xFFFF","cluster":"0xFFFFFFFF","attr":"0xFFFFFFFF"}]'
    LOG.info "Sending command to Subscribe for all attributes with a 0 second minimum time: " + cmd
    sendHubCommand(new hubitat.device.HubAction(cmd, hubitat.device.Protocol.MATTER))
}

List getHubitatEvents(Map descMap) {
    try {
        // Certain clusters have the same set of matching attributes. For those clusters, rather than storing
        // multiple duplicated copies of their transform data, one copy is stored (the "first copy"), and other clusters
        // that have the same attributes (the "aliased clusters") are mapped to the first copy
        Map aliasedCluster = [ 0x040D:0x040C, 0x0413:0x040C, 0x0415:0x040C, 0x042A:0x040C, // Concentraton Measurement Clusters
            0x042B:0x040C, 0x042C:0x040C, 0x042D:0x040C, 0x042E:0x040C, 0x042F:0x040C // More Concentraton Measurement Clusters
            ]
        // The next line determines if you should use an aliased cluster mapping for descMap.clusterInt, or just use clusterInt
        Integer retrieveThisCluster = (descMap.clusterInt in aliasedCluster) ? aliasedCluster.get(descMap.clusterInt) : descMap.clusterInt

        List rEvents = globalAllEventsMap.get(retrieveThisCluster)
            ?.get(descMap.attrInt)
                ?.collect{ Map rValue = [:]
                        rValue << [name:it.attribute] // First copy the attribute string as the name of the event

                        // Now figure out the value for the event using the valueTransform, but first check for null so you don't throw an error applying the transform!
                         if (descMap.decodedValue.is(null)) {
                              rValue <<[value:null]
                         } else if ((it.containsKey("valueTransform")) && (it.valueTransform instanceof Closure)) {
                              rValue << [value:(it.valueTransform(descMap.decodedValue))] // if valueTransform is a closure, apply the transform Closure to the data received from the node
                         } else {
                              rValue << [value: (descMap.decodedValue)]  // else just copy the decoded value
                        }

                        rValue << ( it.units ? [units:(it.units)]  : [:] )

                        // Now let's form a descriptionText string
                        // If you have a descriptionText field and it is a closure, then form the description text using
                        // that Closure supplied with the event's value (the value then can be used in the description)
                        // Else, for a description string using the attribute name and add the value
                          String newDescription
                          if (it.descriptionText && (it.descriptionText instanceof Closure)) {
                              newDescription = it.descriptionText(rValue.value)
                          } else {
                                newDescription = "${StringUtils.splitByCharacterTypeCamelCase(rValue.name).join(" ")} attribute set to ${rValue.value}"
                                if (it.units) { newDescription = newDescription + it.units }
                          }
                        rValue << ( [descriptionText:newDescription])
                        rValue << ( it.isStateChange ? [isStateChange:true]  : [:] ) // Was an isStateChange clause stated, if so, copy it if it is true. False is implied.
                        rValue << ( [clusterInt : (descMap.clusterInt)]) // Event is sent on Hubitat's Event stream to external devices, so let's include some extra cluster info for external device
                        rValue << ( [attrInt : (descMap.attrInt)]) // Event is sent on Hubitat's Event stream to external devices, so let's include some extra attribute info for external device
                        rValue << ( [endpointInt : (descMap.endpointInt)]) // Event is sent on Hubitat's Event stream to external devices, so let's include some extra cluster info for external device
                        rValue << ( [jsonValue: (new JsonBuilder(descMap.decodedValue)) ]) // Event is sent on Hubitat's Event stream to external devices, so let's include original data in JSON form for external device
                    }
        return rEvents
    } catch (AssertionError e) {
        LOG.error "<pre>${e}<br><br>Stack trace:<br>${getStackTrace(e) }"
    } catch(e){
        LOG.error "<pre>${e}<br><br>when processing getHubitatEvents inputs ${descMap}<br><br>Stack trace:<br>${getStackTrace(e) }"
    }
}

// Get all the child devices for a specified endpoint.
List<com.hubitat.app.DeviceWrapper> getChildDeviceListByEndpoint( Map params = [:] ) {
    Map inputs = [ep: null ] << params
    assert inputs.ep instanceof Integer
    childDevices.findAll{ getEndpoint(it) == inputs.ep }
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

// Identify Cluster 0x0003 Enum Data Types (Matter Cluster Spec. Section 1.2.5)
@Field static Map IdentifyTypeEnum =   [ 0:"None",     1:"LightOutput",    2:"VisibleIndicator",    3:"AudibleBeep",    4:"Display",    5:"Actuator"] // Cluste 0x0003
@Field static Map EffectIdentifierEnumType = [ 0:"Blink", 1:"Breathe", 2:"Okay", 0x0B:"ChannelChange", 0xFE:"FinishEffect", 0xFF:"StopEffect"]
@Field static Map EffectVariantEnumType = [0:"Default"]

// OnOff Cluster 0x0006 Enum Data Types (Matter Cluster Spec. Section 1.2.5)
@Field static Map EffectIdentifierEnum = [0:"DelayedAllOff", 1:"DyingLIght"]
@Field static Map DelayedAllOffEffectVariantEnum = [0:"DelayedAllOffEffectVariantEnum", 1:"NoFade", 2:"DelayedOffSlowFade"]
@Field static Map DyingLightEffectVariantEnumType = [0:"DyingLightFadeOff"]

// Level Cluster 0x0008 Enum Data Types (Matter Cluster Spec. Section 1.6.5)
// Haven't needed any yet, so not added!

// Color Cluster 0x0300 Enum Data Types (Matter Cluster Spec. Section 3.2)
// None Defined!

// Basic Information Cluster 0x0028 Enum Data Types (Matter Cluster Spec. Section 11.1.4)
@Field static Map ProductFinishEnumType = [0:"Other", 1:"Matte", 2:"Satin", 3:"Polished", 4:"Rugged", 5:"Fabric"]
@Field static Map ColorEnumType = [
    0:"Black", 1:"Navy", 2:"Green", 3:"Teal", 4:"Maroon", 5:"Purple", 6:"Olive", 7:"Gray",
    8:"Blue", 9:"Lime", 10:"Aqua", 11:"Red", 12:"Fuscia", 13:"Yellow", 14:"White",
    15:"Nickel", 16:"Chrome", 17:"Brass", 18:"Copper", 19:"Silver", 20:"Gold"
    ]

// Air Quality Cluster 0x005B Enum Data Types (Matter Cluster Spec. Section 2.9.5)
@Field static Map AirQualityEnumType = [ 0:"Unknown",     1:"Good",    2:"Fair",    3:"Moderate",    4:"Poor",    5:"VeryPoor",    6:"ExtremelyPoor"]

// Smoke CO Alarm Cluster (Matter Cluster Spec. Section 2.11.5)
@Field static Map AlarmStateEnum = [0:"Normal", 1:"Warning", 2:"Critical" ]
@Field static Map SensitivityEnum = [0:"High", 1:"Standard", 2:"Low"]
@Field static Map ExpressedStateEnum = [0:"Normal", 1:"SmokeAlarm", 2:"COAlarm", 3:"BatteryAlert", 4:"Testing", 5:"HardwareFault", 6:"EndOfService", 7:"InterconnectSmoke", 8:"InterconnectCO"]
@Field static Map MuteStateEnum = [0:"NotMuted", 1:"Muted" ]
@Field static Map EndOfServiceEnum = [0:"Normal", 1:"Expired"]
@Field static Map ContaminationStateEnum = [0:"Normal", 1:"Low", 2:"Warning", 3:"Critical" ]

// Thread Network Diagnostics Cluster 0x0035 (Matter **Core** Spec. Section 11.13.5)
@Field static Map NetworkFaultEnum = [0:"Unspecified", 1:"LinkDown", 2:"HardwareFailure", 3:"NetworkJammed"]
// ConnectionStatusEnum - same as WiFi
@Field static Map RoutingRoleEnum = [0:"Unspecified", 1:"Unassigned", 2:"SleepyEndDevice", 3:"EndDevice", 4:"REED", 5:"Router", 6:"Leader"]
// (Many other types not included)

// Wi-Fi Network Diagnostics Cluster 0x0036 (Matter **Core** Spec. Section 11.14.5)
@Field static Map SecurityTypeEnum = [0:"Unspecified", 1:"None", 2:"WEP", 3:"WPA", 4:"WPA2", 5:"WPA3"]
@Field static Map WiFiVersionEnum = [0:"a", 1:"b", 2:"g", 3:"n", 4:"ac", 5:"ax", 6:"ah"]
@Field static Map AssociationFailureCauseEnum = [0:"Unknown", 1:"AssociationFailed", 2:"AuthenticationFailed", 3:"SsidNotFound"]
@Field static Map ConnectionStatusEnum = [0:"Connected", 1:"NotConnected"]

// Ehternet Network Diagnostics Cluster 0x0037 (Matter **Core** Spec. Section 11.15.5)
@Field static Map PHYRateEnum = [0:"Rate10M", 1:"Rate100M", 2:"Rate1G", 3:"Rate2_5G", 4:"Rate5G", 5:"Rate10G", 6:"Rate40G", 7:"Rate100G", 8:"Rate200G", 9:"Rate400G"]


// PowerSource Cluster 0x002F (Matter **Core** Spec. Section 11.7.5)
@Field static Map WiredFaultEnum = [0:"Unspecified", 1:"OverVoltage", 2:"UnderVoltage"]
@Field static Map BatFaultEnum = [0:"Unspecified", 1:"OverTemp", 2:"UnderTemp"]
@Field static Map BatChargeFaultEnum = [
    0:"Unspecified", 1:"AmbientTooHot", 2:"AmbientTooCold", 3:"BatteryTooHot", 4:"BatteryTooCold", 5:"BatteryAbsent",
    6:"BatteryOverVoltage", 7:"BatteryUnderVoltage", 8:"ChargerOverVoltage", 9:"ChargerUnderVoltage", 10:"SafetyTimeout",
    11:"ChargerOverCurrent", 12:"UnexpectedVoltage", 13:"ExpectedVoltage", 14:"GroundFault", 15:"ChargeSignalFailure", 16:"SafetyTimeout"
    ]
@Field static Map PowerSourceStatusEnum = [ 0:"Unspecified", 1:"Active", 2:"Standby", 3:"Unavailable"]
@Field static Map WiredCurrentTypeEnum = [ 0:"AC", 1:"DC"]
@Field static Map BatChargeLevelEnum = [ 0:"OK", 1:"Warning", 2:"Critical"]
@Field static Map BatReplaceabilityEnum = [ 0:"Unspecified", 1:"NotReplaceable", 2:"UserReplaceable", 3:"FactoryReplaceable"]
@Field static Map BatCommonDesignationEnum = [
    0:"Unspecified", 1:"AAA", 2:"AA", 3:"C", 4:"D", 5:"4v5", 6:"6v0", 7:"9v0",
    8:"1_2AA", 9:"AAAA", 10:"A", 11:"B", 12:"F", 13:"N", 14:"No6", 15:"SubC", 16:"A23",
    17:"A27", 18:"BA5800", 19:"Duplex", 20:"4SR44", 21:"523", 22:"531", 23:"15V0", 24:"22v5",
    25:"30v0", 26:"45v0", 27: "67v5", 28:"J", 29:"CR123A", 30:"CR2", 31:"2CR5", 32:"CR_P2", 33:"CR_V3",
    34:"SR41", 35:"SR43", 36:"SR44", 37:"SR45", 38:"SR48", 39:"SR54", 40:"SR55", 41:"SR57", 42:"SR58",
    43:"SR59", 44:"SR60", 45:"SR63", 46:"SR64", 47:"SR65", 48:"SR66", 49:"SR67", 50:"SR68", 51:"SR69",
    52:"SR516", 53:"SR731", 54:"SR712", 55:"LR932", 56:"A5", 57:"A10", 58:"A13",
    59:"A312", 60:"A675", 61:"AC41E", 62:"10180", 63:"10280", 64:"10440", 65:"14250", 66:"14430",
    67:"14500", 68:"14650", 69:"15270", 70:"16340", 71:"RCR123A", 72:"17500", 73:"17670", 74:"18350",
    75:"18500", 76:"18650", 77:"19670", 78:"2550", 79:"26650", 80:"32600"
    ]
@Field static Map BatApprovedChemistryEnum = [
    0:"Unspecified",
    1:"Alkaline", 2:"LithiumCarbonFluoride", 3:"LithiumChromiumOxide", 4:"LithiumCopperOxide", 5:"LithiumIronDisulfide",
    6:"LithiumManganeseDioxide", 7:"LithiumThionylChloride", 8:"Magnesium", 9:"MercuryOxide", 10:"NickelOxyhydride",
    11:"SilverOxide", 12:"ZincAir", 13:"ZincCarbon", 14:"ZincChloride", 15:"ZincManganeseDioxide",
    16:"LeadAcid", 17:"LithiumCobaltOxide", 18:"LithiumIon", 19:"LithiumIonPolymer", 20:"LithiumIronPhosphate",
    21:"LithiumSulfur", 22:"LithiumTitanate", 23:"NickelCadmium", 24:"NickelHydrogen", 25:"NickelIron",
    26:"NickelMetalHydride", 27:"NickelZinc", 28:"SilverZinc", 29:"SodiumIon", 30:"SodiumSulfur",
    31:"ZincBromide", 32:"ZincCerium",
    ]
@Field static Map BatChargeStateEnum = [ 0:"Unknown", 1:"IsCharging", 2:"IsAtFullCharge", 3:"IsNotCharging", 4:"IsDischarging", 5:"IsTransitioning", ]

// Concentration Measurement Cluster 0x040C (Matter Spec. Section 2.10.5)
@Field static Map MeasurementUnitEnum =   [ 0:"PPM", 1:"PPB", 2:"PPT", 3:"MGM3", 4:"UGM3", 5:"NGM3", 6:"PM3" ]
@Field static Map MeasurementMediumEnum = [ 0:"Air", 1:"Water", 2:"Soil" ]
@Field static Map LevelValueEnum =        [ 0:"Unknown", 1:"Low", 2:"Medium", 3:"High", 4:"Critical" ]

@Field static Closure toTenths = { it / 10}      // Hex to .1 conversion.
@Field static Closure toCenti =  { it / 100}     // Hex to .01 conversion.
@Field static Closure toMilli =  { it / 1000}    // Hex to .001 conversion.
@Field static Closure HexToPercent = { it ? Math.max( Math.round(it / 2.54) , 1) : 0 } // the Math.max check ensures that a value of 1/2.54 does not get changes to 0
@Field static Closure HexToLux =          { Math.pow( 10, (it - 1) / 10000)  as Integer} // convert Matter value to illumination in lx. See Matter Cluster Spec Section 2.2.5.1
@Field static Closure MiredsToKelvin = { ( (it > 0) ? (1000000 / it) : null ) as Integer}

/*
For Closure values in the following structure:
pv = parsed Map value field (descMap.value)
dn = device name - provided as a string
dv = device value - usually the content of the event map's "value" field after pv has been converted by the closure in the "value" field, below..
*/
@Field static Map globalAllEventsMap = [ // Map of clusterInt provides Map of attributeInt provides List of one or more Maps of events
    0x0003:[ // Identify Cluster
        0x0000:[[attribute:"IdentifyTime",                                                      units:" seconds"]],
        0x0001:[[attribute:"IdentifyType",          valueTransform: { IdentifyTypeEnum.get(it)  }]],
        ],
    0x0004:[ // Groups Cluster
        0x0000:[[attribute:"NameSupport"]],
        ],
    0x0006:[ // Switch Cluster
        0x0000:[[attribute:"switch",                valueTransform: { it ? "on" : "off" }],
                [attribute:"OnOff"]],
        0x4000:[[attribute:"GlobalSceneControl"]],
        0x4001:[[attribute:"OnTime",                valueTransform: this.&toTenths,             units:" seconds"]],
        0x4002:[[attribute:"OffWaitTime",           valueTransform: this.&toTenths,             units:" seconds"]],
        ],
    0x0008:[ // Level Cluster
        0x0000:[[attribute:"level",                 valueTransform: this.&HexToPercent,         units:"%"],
                [attribute:"CurrentLevel"]],
        0x0001:[[attribute:"RemainingTime",         valueTransform: this.&toTenths,             units:" seconds"]],
        0x0002:[[attribute:"MinLevel",              valueTransform: this.&HexToPercent,         units:"%"]],
        0x0003:[[attribute:"MaxLevel",              valueTransform: this.&HexToPercent,         units:"%"]],
        0x0004:[[attribute:"CurrentFrequency",                                                  units:"Hz"]],
        0x0005:[[attribute:"MinFrequency",                                                      units:"Hz"]],
        0x0006:[[attribute:"MaxFrequency",                                                      units:"Hz"]],
        0x0010:[[attribute:"OnOffTransitionTime",   valueTransform: this.&toTenths,             units:" seconds"]],
        0x0012:[[attribute:"OnTransitionTime",      valueTransform: this.&toTenths,             units:" seconds"]],
        0x0013:[[attribute:"OffTransitionTime",     valueTransform: this.&toTenths,             units:" seconds"]],
        0x0014:[[attribute:"DefaultMoveRate"]],
        0x000F:[[attribute:"Options"]],
        0x4000:[[attribute:"StartUpCurrentLevel"]],
        ],
    0x001D:[
        0x0000:[[attribute:"DeviceTypeList"]],
        0x0001:[[attribute:"ServerList"]],
        0x0002:[[attribute:"ClientList"]],
        0x0003:[[attribute:"PartsList"]],
        0x0004:[[attribute:"TagList"]],
        ],
    0x001E:[
        0x0000:[[attribute:"Binding"]],
        ],
    0x0028:[ // Basic Information
        0x0000:[[attribute:"DataModelRevision"]],
        0x0001:[[attribute:"VendorName"]],
        0x0002:[[attribute:"VendorID"]],
        0x0003:[[attribute:"ProductName"]],
        0x0004:[[attribute:"ProductID"]],
        0x0005:[[attribute:"NodeLabel"]],
        0x0006:[[attribute:"Location"]],
        0x0007:[[attribute:"HardwareVersion"]],
        0x0008:[[attribute:"HardwareVersionString"]],
        0x0009:[[attribute:"SoftwareVersion"]],
        0x000A:[[attribute:"SoftwareVersionString"]],
        0x000B:[[attribute:"ManufacturingDate"]],
        0x000C:[[attribute:"PartNumber"]],
        0x000D:[[attribute:"ProductURL"]],
        0x000E:[[attribute:"ProductLabel"]],
        0x000F:[[attribute:"SerialNumber"]],
        0x0010:[[attribute:"LocalConfigDisabled"]],
        0x0011:[[attribute:"Reachable"]],
        0x0012:[[attribute:"UniqueID"]],
        0x0013:[[attribute:"CapabilityMinima"]],
        0x0014:[[attribute:"ProductAppearance"]],
        ],
    0x002B:[ // Localization Configuration
        0x0000:[[attribute:"ActiveLocale"]],
        0x0000:[[attribute:"SupportedLocales"]],
        ],
    0x002D:[ // Unit Localization
        0x0000:[[attribute:"TemperatureUnit",         valueTransform: { [0:"Fahrenheit", 1:"Celsius", 2:"Kelvin"].get(toInt(it)) }]],
        ],
    0x002F:[ // Power Source Cluster
        0x0000:[[attribute:"Status",                        valueTransform: { PowerSourceStatusEnum.get(it)}]],
        0x0001:[[attribute:"Order"]],
        0x0002:[[attribute:"Description"]],
        0x0003:[[attribute:"WiredAssessedInputVoltage",     valueTransform: this.&toMilli,  units:"V"]],
        0x0004:[[attribute:"WiredAssessedInputFrequency",   units:"Hz"]],
        0x0005:[[attribute:"WiredCurrentType",              valueTransform: { WiredCurrentTypeEnum.get(it)}]],
        0x0006:[[attribute:"WiredAssessedCurrent",          valueTransform: this.&toMilli, units:"A"]],
        0x0007:[[attribute:"WiredNominalVoltage",           valueTransform: this.&toMilli, units:"V"]],
        0x0008:[[attribute:"WiredMaximumCurrent",           valueTransform: this.&toMilli, units:"A"]],
        0x0009:[[attribute:"WiredPresent"]],
        0x000A:[[attribute:"ActiveWiredFaults"]],
        0x000B:[[attribute:"BatVoltage",                    valueTransform: this.&toMilli, units:"V",       descriptionText: {"Battery Voltage is: ${it}"}]],
        0x000C:[[attribute:"BatPercentRemaining",           valueTransform: { it / 2 }, units:"%",          descriptionText: {"Battery Percent Remaining is: ${it}"}],
                [attribute:"battery",                       valueTransform: { it / 2 }, units:"%",          descriptionText: {"Battery Percent Remaining is: ${it}"}]],
        0x000D:[[attribute:"BatTimeRemaining",                  units:" seconds",                            descriptionText: {"Battery Time Remaining is: ${it}"}]],
        0x000E:[[attribute:"BatChargeLevel",                valueTransform: { BatChargeLevelEnum.get((it)) },   descriptionText: {"Battery Charge Level is: ${it}"}]],
        0x000F:[[attribute:"BatReplacementNeeded",                                                          descriptionText: {"Battery Replacement Needed: ${it}"}]],
        0x0010:[[attribute:"BatReplaceability",             valueTransform: { BatReplaceabilityEnum.get(it)}, descriptionText: {"Battery Replaceability is: ${it}"}]],
        0x0011:[[attribute:"BatPresent",                                                descriptionText: {"Battery Present: ${it}"}]],
        0x0012:[[attribute:"ActiveBatFaults",                                           descriptionText: {"Active Battery Faults are: ${it}"}]],
        0x0013:[[attribute:"BatReplacementDescription",                                 descriptionText: {"Battery Replacement Description: ${it}"}]],
        0x0014:[[attribute:"BatCommonDesignation",          valueTransform: { BatCommonDesignationEnum.get(it)}, descriptionText: {"Battery Common  Designation: ${it}"}]],
        0x0015:[[attribute:"BatANSIDesignation",                                        descriptionText: {"Battery ANSI C18 Designation: ${it}"}]],
        0x0016:[[attribute:"BatIECDesignation",                                         descriptionText: {"Battery IEC 60086 Designation: ${it}"}]],
        0x0017:[[attribute:"BatApprovedChemistry",          valueTransform: { BatApprovedChemistryEnum.get(it)}, descriptionText: {"Battery Approved Chemistry: ${it}"}]],
        0x0018:[[attribute:"BatCapacity",                       units:"mAh",                descriptionText: {"Battery Capacity: ${it} mAH"}]],
        0x0019:[[attribute:"BatQuantity",                                               descriptionText: {"Battery Quantity: ${it}"}]],
        0x001A:[[attribute:"BatChargeState",                valueTransform: { BatChargeState.get(it) },         descriptionText: {"Battery Charge State: ${it}"}]],
        0x001B:[[attribute:"BatTimeToFullCharge",               units:" seconds",            descriptionText: {"Battery Time To Full Charge: ${it} seconds"}]],
        0x001C:[[attribute:"BatFunctionalWhileCharging",                                descriptionText: {"Battery Functional While Charging: ${it}"}]],
        0x001D:[[attribute:"BatChargingCurrent",                                        descriptionText: {"Battery Charging Current: ${it}"}]],
        0x001E:[[attribute:"ActiveBatChargeFaults",                                     descriptionText: {"Active Battery Charge Faults: ${it}"}]],
        0x001F:[[attribute:"EndpointList",                                              descriptionText: {"Power Source Endpoint List: ${it}"}]],
        ],

    0x0035:[ // Thread Diagnostics
        0x0000:[[attribute:"Channel"]],
        0x0001:[[attribute:"RoutingRole", valueTransform: { RoutingRoleEnum.get(it)}]],
        0x0002:[[attribute:"NetworkName"]],
        0x0003:[[attribute:"PanId"]],
        0x0004:[[attribute:"ExtendedPanId"]],
        0x0005:[[attribute:"MeshLocalPrefix"]],
        0x0006:[[attribute:"OverrunCount"]],
        0x0007:[[attribute:"NeighborTable"]],
        0x0008:[[attribute:"RouteTable"]],
        0x0009:[[attribute:"PartitionId"]],
        0x000A:[[attribute:"Weighting"]],
        0x000B:[[attribute:"DataVersion"]],
        0x000C:[[attribute:"StableDataVersion"]],
        0x000D:[[attribute:"LeaderRouterId"]],
        0x000E:[[attribute:"DetachedRoleCount"]],
        0x000F:[[attribute:"ChildRoleCount"]],

        0x0010:[[attribute:"RouterRoleCount"]],
        0x0011:[[attribute:"LeaderRoleCount"]],
        0x0012:[[attribute:"AttachedAttemptCount"]],
        0x0013:[[attribute:"PartitionIdChangeCount"]],
        0x0014:[[attribute:"BetterPartitionAttachAttemptCount"]],
        0x0015:[[attribute:"ParentChangeCount"]],
        0x0016:[[attribute:"TxTotalCount"]],
        0x0017:[[attribute:"TxUnicastCount"]],
        0x0018:[[attribute:"TxBroadcastCount"]],
        0x0019:[[attribute:"TxAckRequestedCount"]],
        0x001A:[[attribute:"TxAcked"]],
        0x001B:[[attribute:"TxNoAckRequestedCount"]],
        0x001C:[[attribute:"TxDataCount"]],
        0x001D:[[attribute:"TxDataPollCount"]],
        0x001E:[[attribute:"TxBeaconCount"]],
        0x001F:[[attribute:"TxBeaconRequestCount"]],

        0x0020:[[attribute:"TxOtherCount"]],
        0x0021:[[attribute:"TxRetryCount"]],
        0x0022:[[attribute:"TxDirectMaxRetryExpiryCount"]],
        0x0023:[[attribute:"TxIndirectMaxRetryExpiryCount"]],
        0x0024:[[attribute:"TxErrCcaCount"]],
        0x0025:[[attribute:"TxErrAbortCount"]],
        0x0026:[[attribute:"TxErrBusyChannelCount"]],
        0x0027:[[attribute:"RxTotalCount"]],
        0x0028:[[attribute:"RxUnicastCount"]],
        0x0029:[[attribute:"RxBroadcastCount"]],
        0x002A:[[attribute:"RxDataCount"]],
        0x002B:[[attribute:"RxDataPollCount"]],
        0x002C:[[attribute:"RxBeaconCount"]],
        0x002D:[[attribute:"RxBeaconRequestCount"]],
        0x002E:[[attribute:"RxOtherCount"]],
        0x002F:[[attribute:"RxAddressFilteredCount"]],
        0x0030:[[attribute:"RxDestAddrFilteredCount"]],
        0x0031:[[attribute:"RxDuplicatedCount"]],
        0x0032:[[attribute:"RxErrNoFrameCount"]],
        0x0033:[[attribute:"RxErrUnknownNeighborCount"]],
        0x0034:[[attribute:"RxErrInvalidSrcAddrCount"]],
        0x0035:[[attribute:"RxErrSecCount"]],
        0x0036:[[attribute:"RxErrFcsCount"]],
        0x0037:[[attribute:"RxErrOtherCount"]],
        0x0038:[[attribute:"ActiveTimestamp"]],
        0x0039:[[attribute:"PendingTimestamp"]],
        0x003A:[[attribute:"Delay"]],
        // 0x003B:[[attribute:"SecurityPolicy"]],
        // 0x003C:[[attribute:"ChannelPage0Mask"]],
        // 0x003D:[[attribute:"OperationalDatasetComponents"]],
        // 0x003E:[[attribute:"ActiveNetworkFaults"]],
        ],
    0x0036:[ // WiFi Diagnostics
        0x0000:[[attribute:"BSSID"]],
        0x0001:[[attribute:"SecurityType", valueTransform: { SecurityTypeEnum.get(it)}]],
        0x0002:[[attribute:"WiFiVersion", valueTransform: { WiFiVersionEnum.get(it)}]],
        0x0003:[[attribute:"ChannelNumber"]],
        0x0004:[[attribute:"RSSI"]],
        0x0005:[[attribute:"BeaconLostCount"]],
        0x0006:[[attribute:"BeaconRxCount"]],
        0x0007:[[attribute:"PacketMulticastRxCount"]],
        0x0008:[[attribute:"PacketMulticastTxCount"]],
        0x0009:[[attribute:"PacketUnicastRxCount"]],
        0x000A:[[attribute:"PacketUnicastTxCount"]],
        0x000B:[[attribute:"CurrentMaxRate"]],
        0x000C:[[attribute:"OverrunCount"]],
        ],
    0x003B:[ // Generic Switch Cluster
        0x0000:[[attribute:"NumberOfPositions"]],
        0x0001:[[attribute:"CurrentPosition"]],
        0x0002:[[attribute:"MultiPressMax"]],
        ],
    0x0040:[ // Fixed Label Cluster, Core Spec 9.8
        0x0000:[[attribute:"FixedLabelList"]], // Note attribute name change to prevent confusion between 0x0040 and 0x0041
        ],
    0x0041:[ // Fixed Label Cluster, Core Spec 9.9
        0x0000:[[attribute:"UserLabelList"]], // Note attribute name change to prevent confusion between 0x0040 and 0x0041
        ],
    0x0045:[ // Boolean State
        0x0000:[[attribute:"StateVale",],
                [attribute:"contact",    valueTransform: { it ? "closed" : "open"}]], //
        ],
    0x0046: [ // ICD Management Cluster
        0x0000:[[attribute:"IdleModeInterval"]],
        0x0001:[[attribute:"ActiveModeInterval"]],
        0x0002:[[attribute:"ActiveModeThreshold"]],
        0x0003:[[attribute:"RegisteredClients"]],
        0x0004:[[attribute:"ICDCounter"]],
        0x0005:[[attribute:"ClientsSupportedPerFabric"]],
        ],
    0x0050: [ // Mode Select Cluster
        0x0000:[[attribute:"Description"]],
        0x0001:[[attribute:"StandardNamespace"]],
        0x0002:[[attribute:"SupportedModes"]],
        0x0003:[[attribute:"CurrentMode"]],
        0x0004:[[attribute:"StartUpMode"]],
        0x0005:[[attribute:"OnMode"]],
        ],
    0x0300:[ // Color Control Cluster.  Only covering the most common ones for Hue at the moment!
        0x0000:[ // Hue
                [attribute:"hue",  valueTransform: this.&HexToPercent, units:"%"],  //  This is the Hubitat name/value
                [attribute:"CurrentHue",                   ],      // This is the Matter name / value
        ],
        0x0001:[[attribute:"saturation", valueTransform: this.&HexToPercent, units:"%"],      //  This is the Hubitat name/value
                [attribute:"CurrentSaturation",                                         ]       // This is the Matter name / value
        ],
        0x0002:[[attribute:"RemainingTime", valueTransform: this.&toTenths, units:" seconds"]],
        0x0003:[[attribute:"CurrentX"]],
        0x0004:[[attribute:"CurrentY"]],
        0x0005:[[attribute:"DriftCompensation"]],
        0x0006:[[attribute:"CompensationText"]],

        0x0007:[[attribute:"colorTemperature", valueTransform: this.&MiredsToKelvin, units: "°K"],
                [attribute:"ColorTemperatureMireds",    units: "Mireds"],
        ],
        0x0008:[[attribute:"colorMode",                 valueTransform: {[0:"RGB", 1:"CurrentXY", 2:"CT"].get(it)}], // This is how Hubitat names it
                [attribute:"ColorMode",                     ] // This is how Matter names it!
        ],

        0x0010:[[attribute:"NumberOfPrimaries"]],

        0x0011:[[attribute:"Primary1X"]],
        0x0012:[[attribute:"Primary1Y"]],
        0x0013:[[attribute:"Primary1Intensity"]],

        0x0015:[[attribute:"Primary2X"]],
        0x0016:[[attribute:"Primary2Y"]],
        0x0017:[[attribute:"Primary2Intensity"]],

        0x0019:[[attribute:"Primary3X"]],
        0x001A:[[attribute:"Primary3Y"]],
        0x001B:[[attribute:"Primary3Intensity"]],

        0x0020:[[attribute:"Primary4X"]],
        0x0021:[[attribute:"Primary4Y"]],
        0x0022:[[attribute:"Primary4Intensity"]],

        0x0024:[[attribute:"Primary5X"]],
        0x0025:[[attribute:"Primary5Y"]],
        0x0026:[[attribute:"Primary5Intensity"]],

        0x0028:[[attribute:"Primary6X"]],
        0x0029:[[attribute:"Primary6Y"]],
        0x002A:[[attribute:"Primary6Intensity"]],

        0x0020:[[attribute:"WhitePointX"]],
        0x0021:[[attribute:"WhitePointY"]],

        0x0030:[[attribute:"ColorPointRX"]],
        0x0031:[[attribute:"ColorPointRY"]],
        0x0032:[[attribute:"ColorPointRIntensity"]],

        0x0033:[[attribute:"ColorPointGX"]],
        0x0034:[[attribute:"ColorPointGY"]],
        0x0036:[[attribute:"ColorPointGIntensity"]],

        0x0037:[[attribute:"ColorPointBX"]],
        0x0038:[[attribute:"ColorPointBY"]],
        0x003A:[[attribute:"ColorPointBIntensity"]],

        0x4001:[[attribute:"EnhancedColorMode"]],
        0x4002:[[attribute:"ColorLoopActive"]],
        0x4003:[[attribute:"ColorLoopDirection"]],
        0x4004:[[attribute:"ColorLoopTime"]],
        0x4005:[[attribute:"ColorLoopStartEnhancedHue"]],
        0x4006:[[attribute:"ColorLoopStoredEnhancedHue"]],

        0x400A:[[attribute:"ColorCapabilities",         valueTransform: { List capability = [];
                                                                if (it & 0b0000_0001) capability << "HS";
                                                                if (it & 0b0000_0010) capability << "EHUE";
                                                                if (it & 0b0000_0100) capability << "CL";
                                                                if (it & 0b0000_1000) capability << "XY";
                                                                if (it & 0b0001_0000) capability << "CT";
                                                                return capability
            } ]
        ],
        0x400B:[[attribute:"ColorTemperaturePhysicalMinMireds",  units: "Mireds"],
                [attribute:"ColorTemperatureMaxKelvin",              valueTransform: this.&MiredsToKelvin, units: "°K"]],
        0x400C:[[attribute:"ColorTemperaturePhysicalMaxMireds",  units: "°M"],
                [attribute:"ColorTemperatureMinKelvin",              valueTransform: this.&MiredsToKelvin, units: "°K"]],
        0x400D:[[attribute:"CoupleColorTempToLevelMinMireds"]],
        0x4010:[[attribute:"StartUpColorTemperatureMireds",      units: "°M"],
                [attribute:"StartUpColorTemperatureKelvin",              valueTransform: this.&MiredsToKelvin, units: "°K"]],
        ],
    0x0400:[ // Illuminance Measurement
        0x0000:[ [attribute:"illuminance",             valueTransform: this.&HexToLux, units:"lx"], // This is the Hubitat name
                 [attribute:"MeasuredValue",           valueTransform: this.&HexToLux, units:"lx"], // This is the Matter name
        ],
        0x0001:[ [attribute:"MinMeasuredValueLux",     valueTransform: this.&HexToLux, units:"lx"]],
        0x0002:[ [attribute:"MaxMeasuredValueLux",     valueTransform: this.&HexToLux, units:"lx"]],
        0x0003:[ [attribute:"LuxMeasurementTolerance", valueTransform: this.&HexToLux, units:"lx"]],
        0x0004:[ [attribute:"LightSensorType",         valueTransform: {[0:"Photodiode", 1:"CMOS"].get(it) }]],
        ],
    0x0402:[ // Temperature Measurement
        0x0000:[ [attribute:"temperature",              valueTransform: this.&toCenti, units:"°C"],
                 [attribute:"TempMeasuredValue",        valueTransform: this.&toCenti, units:"°C"],
        ],
        0x0001:[ [attribute:"TempMinMeasuredValue",     valueTransform: this.&toCenti, units:"°C"]],
        0x0002:[ [attribute:"TempMaxMeasuredValue",     valueTransform: this.&toCenti, units:"°C"]],
        0x0003:[ [attribute:"TempTolerance",            valueTransform: this.&toCenti, units:"°C"]],
        ],
    // 0x0403:[ // Pressure Measurement. Add if a supporting device comes to market for this!
    // 0x0404:[ // Flow Measurement. Add if a supporting device comes to market for this!
    0x0405:[ // Relative Humidty Measurement
        0x0000:[[attribute:"MeasuredValue",     valueTransform: this.&toCenti, units:"%"]],
        0x0001:[[attribute:"MinMeasuredValue",  valueTransform: this.&toCenti, units:"%"]],
        0x0002:[[attribute:"MaxMeasuredValue",  valueTransform: this.&toCenti, units:"%"]],
        0x0003:[[attribute:"Tolerance",         valueTransform: this.&toCenti, units:"%"]],
        ],
    0x0406:[ // Occupancy Measurement
        0x0000:[[attribute:"motion",                        valueTransform: { it ? "active" : "inactive" }],
                [attribute:"presence",                      valueTransform: { it ? "active" : "inactive" }],
                [attribute:"Occupancy",                     units:"bitmap"]],
        0x0001:[[attribute:"OccupancySensorType",           valueTransform: { [0:"PIR", 1:"Ultrasonic", 2:"PIRAndUltrasonic", 3:"PhysicalContact"].get(it)}]],
        0x0001:[[attribute:"OccupancySensorTypeBitmap"]],
        0x0010:[[attribute:"PIROccupiedToUnoccupiedDelay",                  units:" seconds"]],
        0x0011:[[attribute:"PIRUnoccupiedToOccupiedDelay",                  units:" seconds"]],
        0x0012:[[attribute:"PIRUnoccupiedToOccupiedThreshold",              units:" events"]],
        0x0020:[[attribute:"UltrasonicOccupiedToUnoccupiedDelay",           units:" seconds"]],
        0x0031:[[attribute:"UltrasonicUnoccupiedToOccupiedDelay",           units:" seconds"]],
        0x0032:[[attribute:"UltrasonicUnoccupiedToOccupiedThreshold",       units:" events"]],
        0x0030:[[attribute:"PhysicalContactOccupiedToUnoccupiedDelay",      units:" seconds"]],
        0x0031:[[attribute:"PhysicalContactUnoccupiedToOccupiedDelay",      units:" seconds"]],
        0x0032:[[attribute:"PhysicalContactUnoccupiedToOccupiedThreshold",  units:" events"]],
        ],
    // 0x0407:[ // Leaf Wetness Measurement. Add if a device comes to market for this!
    // 0x0408:[ // Soil Moisture Measurement. Add if a device comes to market for this!
    // 0x040C: concentrationMeasurementCluster, // CO
    0x040C: [
        0x0000:[[attribute:"MeasuredValue"]],
        0x0001:[[attribute:"MinMeasuredValue"]],
        0x0002:[[attribute:"MaxMeasuredValue"]],
        0x0003:[[attribute:"PeakMeasuredValue"]],
        0x0004:[[attribute:"PeakMeasuredValueWindow", units:" seconds"]],
        0x0005:[[attribute:"AverageMeasuredValue"]],
        0x0006:[[attribute:"AverageMeasuredValueWindow"]],
        0x0007:[[attribute:"Uncertainty"]],
        0x0008:[[attribute:"MeasurementUnit",               valueTransform: { MeasurementUnitEnum.get(it) }]],
        0x0009:[[attribute:"MeasurementMedium",             valueTransform: { MeasurementMediumEnum.get(it) }]],
        0x000A:[[attribute:"LevelValue",                    valueTransform: { LevelValueEnum.get(it) }          ]]
        ],
    // 0x040D: concentrationMeasurementCluster, // CO2. Aliases to 0x040C
    // 0x0413: concentrationMeasurementCluster, // NO2. Aliases to 0x040C
    // 0x0415: concentrationMeasurementCluster, // O3. Aliases to 0x040C
    // 0x042A: concentrationMeasurementCluster, // PM2.5. Aliases to 0x040C
    // 0x042B: concentrationMeasurementCluster, // Formaldehyde. Aliases to 0x040C
    // 0x042C: concentrationMeasurementCluster, // PM1. Aliases to 0x040C
    // 0x042D: concentrationMeasurementCluster, // PM10. Aliases to 0x040C
    // 0x042E: concentrationMeasurementCluster, // TVOC. Aliases to 0x040C
    // 0x042F: concentrationMeasurementCluster, // Radon (Rn). Aliases to 0x040C
    0x005B:[ // Air Quality
        0x0000:[[attribute:"AirQuality", valueTransform: { AirQualityEnumType.get(it) }]],
        ],
    0x005C:[ // Smoke and CO Alarm
        0x0000:[[attribute:"ExpressedState",            valueTransform: { ExpressedStateEnum.get(it) }]],
        0x0001:[[attribute:"SmokeState",                valueTransform: { AlarmStateEnum.get(it) }]],
        0x0002:[[attribute:"COState",                   valueTransform: { AlarmStateEnum.get(it) }]],
        0x0003:[[attribute:"BatteryAlert",              valueTransform: { AlarmStateEnum.get(it) }]],
        0x0004:[[attribute:"DeviceMuted",               valueTransform: { MuteStateEnum.get(it) }]],
        0x0005:[[attribute:"TestInProgress"]],
        0x0006:[[attribute:"HardwareFaultAlert"]],
        0x0007:[[attribute:"EndOfServiceAlert",         valueTransform: { EndOfServiceEnum.get(it) }]],
        0x0008:[[attribute:"InterconnectSmokeAlarm",    valueTransform: { AlarmStateEnum.get(it) }]],
        0x0009:[[attribute:"InterconnectCOAlarm",       valueTransform: { AlarmStateEnum.get(it) }]],
        0x000A:[[attribute:"ContaminationState",        valueTransform: { ContaminationStateEnum.get(it) }]],
        0x000B:[[attribute:"SmokeSensitivityLevel",     valueTransform: { SensitivityEnum.get(it) }]],
        0x000C:[[attribute:"ExpiryDate",                units:"epoch-s"]],
        ],
    0x040C:[// Concentration Measurement Cluster (Matter Spec Section 2.10)
        0x0004:[[attribute:"PeakMeasuredValueWindow"]],
        0x0008:[[attribute:"MeasurementUnit",       valueTransform: { MeasurementUnitEnum.get(it) }]],
        0x0009:[[attribute:"MeasurementMedium",     valueTransform: { MeasurementMediumEnum.get(it) }]],
        0x000A:[[attribute:"LevelValue",            valueTransform: { LevelValueEnum.get(it) }]],
        ],
    0x130AFC01:[ // Eve Energy Custom Cluster
        0x130A0008:[[attribute:"voltage",             units:"V"]],
        0x130A0009:[[attribute:"amperage",            units:"A"]],
        0x130A000A:[[attribute:"power",               units:"W"]],
        0x130A000B:[[attribute:"EveWattAccumulated"]],
        0x130A000E:[[attribute:"EveWattAccumulatedControlPoint",    ]]
        ],
    ]

@Field static ConcurrentHashMap globalDataStorage = new ConcurrentHashMap(32, 0.75, 1) // Intended to Store info. that does not change. Default is static
