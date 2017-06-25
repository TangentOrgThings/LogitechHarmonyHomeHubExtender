/**
 *  Copyright 2015 SmartThings
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *  for the specific language governing permissions and limitations under the License.
 *
 */
 
def getDriverVersion () {
	return "1.14"
}

def getAssociationGroup () {
  return 1
}

metadata {
  definition (name: "Logitech Harmony Home Hub Extender", namespace: "TangentOrgThings", author: "Brian Aker") {
    capability "Refresh"
    fingerprint type: "0207", mfr: "007F", prod: "0001", model: "0001", deviceJoinName: "Logitech Harmony Home Hub Extender" // cc: "20,22,56,59,72,73,7A,85,86,98,5E", role: "00", ff: "8500", ui: "8500"
    
    attribute "Associated", "string"
    attribute "driverVersion", "string"
    attribute "FirmwareMdReport", "string"
    attribute "Manufacturer", "string"
    attribute "ManufacturerCode", "string"
    attribute "MSR", "string"
    attribute "ProduceTypeCode", "string"
    attribute "ProductCode", "string"
    attribute "WakeUp", "string"
    attribute "WirelessConfig", "string"
  }

  simulator {
  }

  tiles {
    standardTile("state", "device.state", width: 2, height: 2) {
      state 'connected', icon: "st.unknown.zwave.static-controller", backgroundColor:"#ffffff"
    }
    standardTile("refresh", "device.contact", width: 2, height: 2, inactiveLabel: false, decoration: "flat") {
      state "default", label:'', action:"refresh.refresh", icon:"st.secondary.refresh"
    }
    
    main "state"
    details(["state", "refresh"])
  }
}

def parse(String description) {
  def result = null

  log.debug "PARSE: ${description}"
  if (description.startsWith("Err")) {
    if (description.startsWith("Err 106")) {
      if (state.sec) {
        log.debug description
      } else {
        result = createEvent(
          descriptionText: "This device failed to complete the network security key exchange. If you are unable to control it via SmartThings, you must remove it from your network and add it again.",
          eventType: "ALERT",
          name: "secureInclusion",
          value: "failed",
          isStateChange: true,
        )
      }
    } else {
      result = createEvent(value: description, descriptionText: description, isStateChange: true)
    }
  } else if (description != "updated") {
    def cmd = zwave.parse(description)
	
    if (cmd) {
      result = zwaveEvent(cmd)
      
      if (!result) {
        log.warning "Parse Failed and returned ${result} for command ${cmd}"
        result = createEvent(value: description, descriptionText: description)
      } else {
        log.debug "RESULT: ${result}"
      }
    } else {
      log.info "zwave.parse() failed: ${description}"
      result = createEvent(value: description, descriptionText: description)
    }
  }
    
  return result
}

private List loadEndpointInfo() {
	if (state.endpointInfo) {
		state.endpointInfo
	} else if (device.currentValue("epInfo")) {
		fromJson(device.currentValue("epInfo"))
	} else {
		[]
	}
}

def zwaveEvent(physicalgraph.zwave.commands.multichannelv3.MultiChannelEndPointReport cmd) {
	updateDataValue("endpoints", cmd.endPoints.toString())
	if (!state.endpointInfo) {
		state.endpointInfo = loadEndpointInfo()
	}
	if (state.endpointInfo.size() > cmd.endPoints) {
		cmd.endpointInfo
	}
	state.endpointInfo = [null] * cmd.endPoints
	//response(zwave.associationV2.associationGroupingsGet())
	[ createEvent(name: "epInfo", value: util.toJson(state.endpointInfo), displayed: false, descriptionText:""),
	  response(zwave.multiChannelV3.multiChannelCapabilityGet(endPoint: 1)) ]
}

def zwaveEvent(physicalgraph.zwave.commands.multichannelv3.MultiChannelCapabilityReport cmd) {
	def result = []
	def cmds = []
	if(!state.endpointInfo) state.endpointInfo = []
	state.endpointInfo[cmd.endPoint - 1] = cmd.format()[6..-1]
	if (cmd.endPoint < getDataValue("endpoints").toInteger()) {
		cmds = zwave.multiChannelV3.multiChannelCapabilityGet(endPoint: cmd.endPoint + 1).format()
	} else {
		log.debug "endpointInfo: ${state.endpointInfo.inspect()}"
	}
	result << createEvent(name: "epInfo", value: util.toJson(state.endpointInfo), displayed: false, descriptionText:"")
	if (cmds) {
      result << response(cmds)
    }
	
    return result
}

def zwaveEvent(physicalgraph.zwave.commands.associationv2.AssociationGroupingsReport cmd) {
	state.groups = cmd.supportedGroupings
	if (cmd.supportedGroupings > 1) {
		[response(zwave.associationGrpInfoV1.associationGroupInfoGet(groupingIdentifier:2, listMode:1))]
	}
}

def zwaveEvent(physicalgraph.zwave.commands.associationgrpinfov1.AssociationGroupCommandListReport cmd) {
  log.debug "AssociationGroupCommandListReport: $cmd"
  createEvent(descriptionText: "$device.displayName AssociationGroupCommandListReport: $cmd", displayed: true)
}

def zwaveEvent(physicalgraph.zwave.commands.associationgrpinfov1.AssociationGroupNameGet cmd) {
  log.debug "AssociationGroupNameGet: $cmd"
  createEvent(descriptionText: "$device.displayName AssociationGroupNameGet: $cmd", displayed: true)
}

def zwaveEvent(physicalgraph.zwave.commands.languagev1.LanguageReport cmd) {
  log.debug "AssociationGroupNameGet: $cmd"
  createEvent(descriptionText: "$device.displayName AssociationGroupNameGet: $cmd", displayed: true)
}

def zwaveEvent(physicalgraph.zwave.commands.associationgrpinfov1.AssociationGroupInfoReport cmd) {
	def result = []

	for (def i = 2; i <= state.groups; i++) {
		result << response(zwave.multiChannelAssociationV2.multiChannelAssociationSet(groupingIdentifier:i, nodeId:zwaveHubNodeId))
	}
	
    return result
}

def zwaveEvent(physicalgraph.zwave.commands.multichannelv3.MultiChannelCmdEncap cmd) {
	def encapsulatedCommand = cmd.encapsulatedCommand([0x32: 3, 0x25: 1, 0x20: 1])
	if (encapsulatedCommand) {
		if (state.enabledEndpoints.find { it == cmd.sourceEndPoint }) {
			def formatCmd = ([cmd.commandClass, cmd.command] + cmd.parameter).collect{ String.format("%02X", it) }.join()
			createEvent(name: "epEvent", value: "$cmd.sourceEndPoint:$formatCmd", isStateChange: true, displayed: false, descriptionText: "(fwd to ep $cmd.sourceEndPoint)")
		} else {
			zwaveEvent(encapsulatedCommand, cmd.sourceEndPoint as Integer)
		}
	}
}



def zwaveEvent(physicalgraph.zwave.commands.securityv1.SecurityMessageEncapsulation cmd) 
{
	log.debug "secure message happened"
	def event = [isStateChange: true]
	event.linkText = device.label ?: device.name
	event.descriptionText = "$event.linkText: ${cmd.encapsulatedCommand()} [secure]"
	event
}

def zwaveEvent(physicalgraph.zwave.commands.crc16encapv1.Crc16Encap cmd) {
	def versions = [0x31: 2, 0x30: 1, 0x84: 1, 0x89: 1, 0x9C: 1, 0x70: 2]
	// def encapsulatedCommand = cmd.encapsulatedCommand(versions)
	def version = versions[cmd.commandClass as Integer]
	def ccObj = version ? zwave.commandClass(cmd.commandClass, version) : zwave.commandClass(cmd.commandClass)
	def encapsulatedCommand = ccObj?.command(cmd.command)?.parse(cmd.data)
	if (encapsulatedCommand) {
		zwaveEvent(encapsulatedCommand)
	}
}

def zwaveEvent(physicalgraph.zwave.Command cmd) 
{
	log.debug "Command: $cmd"
	def event = [isStateChange: true]
	event.linkText = device.label ?: device.name
	event.descriptionText = "$event.linkText: $cmd"
	event
}

def zwaveEvent(physicalgraph.zwave.commands.manufacturerspecificv2.ManufacturerSpecificReport cmd) {
  def result = []
  
  def manufacturerCode = String.format("%04X", cmd.manufacturerId)
  def productTypeCode = String.format("%04X", cmd.productTypeId)
  def productCode = String.format("%04X", cmd.productId)
  def wirelessConfig = "ZWP"
  
  result << createEvent(name: "ManufacturerCode", value: manufacturerCode)
  result << createEvent(name: "ProduceTypeCode", value: productTypeCode)
  result << createEvent(name: "ProductCode", value: productCode)
  result << createEvent(name: "WirelessConfig", value: wirelessConfig)

  def msr = String.format("%04X-%04X-%04X", cmd.manufacturerId, cmd.productTypeId, cmd.productId)
  updateDataValue("MSR", msr)
  updateDataValue("manufacturer", "Logitech")
  if (!state.manufacturer) {
    state.manufacturer= "Logitech"
  }
  
  result << createEvent([name: "MSR", value: "$msr", descriptionText: "$device.displayName", isStateChange: false])
  result << createEvent([name: "Manufacturer", value: "${cmd.manufacturerName}", descriptionText: "$device.displayName", isStateChange: false])
  
  return result
}

def zwaveEvent(physicalgraph.zwave.commands.versionv1.VersionReport cmd) {
  def text = "$device.displayName: firmware version: ${cmd.applicationVersion}.${cmd.applicationSubVersion}, Z-Wave version: ${cmd.zWaveProtocolVersion}.${cmd.zWaveProtocolSubVersion}"
  state.firmwareVersion = cmd.applicationVersion+'.'+cmd.applicationSubVersion 
  createEvent([name: "firmwareVersion", value: "V ${state.firmwareVersion}", descriptionText: "$text", isStateChange: false])
}

def zwaveEvent(physicalgraph.zwave.commands.wakeupv2.WakeUpIntervalReport cmd) 
{
	log.debug "WakeUpIntervalReport"
	def event = [isStateChange: true]
	event.linkText = device.label ?: device.name
	event.descriptionText = "$event.linkText WakeUpIntervalReport: $cmd"
    result << createEvent([descriptionText: event.descriptionText, isStateChange: true, displayed: true])
}

def zwaveEvent(physicalgraph.zwave.commands.deviceresetlocallyv1.DeviceResetLocallyNotification cmd) {
  def result = []
  log.debug ("DeviceResetLocallyNotification()")
  
  result << createEvent([descriptionText: cmd.toString(), isStateChange: true, displayed: true])
  // result << response(command(zwave.associationV2.associationGet(groupingIdentifier: 1)))
  
  return result
}

def zwaveEvent(physicalgraph.zwave.commands.associationv2.AssociationReport cmd) {
  def result = []
  
  log.debug ("AssociationReport()")
  
  if (cmd.groupingIdentifier == getAssociationGroup()) {
    def string_of_assoc = ""
    cmd.nodeId.each {
      string_of_assoc += "${it}, "
    }
    def lengthMinus2 = string_of_assoc.length() - 3
    def final_string = string_of_assoc.getAt(0..lengthMinus2)
    
    if (cmd.nodeId.any { it == zwaveHubNodeId }) {
      Boolean isStateChange = state.isAssociated ?: false
      result << createEvent(name: "Associated",
                            value: "${final_string}", 
                            descriptionText: "${final_string}",
                            displayed: true,
                            isStateChange: isStateChange)
      
      state.isAssociated = true
    } else {
      Boolean isStateChange = state.isAssociated ? true : false
      result << createEvent(name: "Associated",
                          value: "",
                          descriptionText: "${final_string}",
                          displayed: true,
                          isStateChange: isStateChange)
    }
    state.isAssociated = false
  } else {
    Boolean isStateChange = state.isAssociated ? true : false
    result << createEvent(name: "Associated",
                          value: "misconfigured",
                          descriptionText: "misconfigured group ${cmd.groupingIdentifier}",
                          displayed: true,
                          isStateChange: isStateChange)
  }
  
  if (state.isAssociated == false) {
  /*
    result << response(commands([ zwave.associationV2.associationSet(groupingIdentifier: getAssociationGroup(), nodeId: [1,zwaveHubNodeId]),
                                  zwave.associationV2.associationGet(groupingIdentifier: getAssociationGroup())
                                  ], 1000))
                                  */
  }
    
  return result
}

def configure() {
	response(commands([
		zwave.multiChannelV3.multiChannelEndPointGet(),
        // zwave.associationV2.associationSet(groupingIdentifier:1, nodeId:zwaveHubNodeId),
        zwave.associationV2.associationGet(groupingIdentifier:1),
        zwave.associationGrpInfoV1.associationGroupCommandListGet(),
        zwave.associationGrpInfoV1.associationGroupInfoGet(),
        zwave.associationGrpInfoV1.associationGroupNameGet(),
        zwave.versionv1.VersionGet(),
        // zwave.zwaveCmdClassV1.cmdSucNodeId(),
        zwave.manufacturerSpecificV2.manufacturerSpecificGet()
	], 800))
}

def installed() {
  log.debug ("installed()")
}

def updated() {
  log.debug "updated()"
  sendEvent(name: "driverVersion", value: getDriverVersion(), descriptionText: getDriverVersion(), isStateChange: true, displayed:true)
  state.driverVersion = getDriverVersion()
}

def refresh() {
  commands([
    zwave.associationV1.associationGet(groupingIdentifier:1),
    zwave.versionV1.versionGet(),
    // zwave.wakeupv2.WakeUpIntervalGet().format(),
    zwave.manufacturerSpecificV2.manufacturerSpecificGet()
  ])
}

def epCmd(Integer ep, String cmds) {
	def result
	if (cmds) {
		def header = state.sec ? "988100600D00" : "600D00"
		result = cmds.split(",").collect { cmd -> (cmd.startsWith("delay")) ? cmd : String.format("%s%02X%s", header, ep, cmd) }
	}
	result
}

def enableEpEvents(enabledEndpoints) {
	state.enabledEndpoints = enabledEndpoints.split(",").findAll()*.toInteger()
	null
}

private command(physicalgraph.zwave.Command cmd) {
  if (state.sec) {
    zwave.securityV1.securityMessageEncapsulation().encapsulate(cmd).format()
  } else {
    cmd.format()
  }
}

private commands(commands, delay=200) {
  delayBetween(commands.collect{ command(it) }, delay)
}

private encap(cmd, endpoint) {
	if (endpoint) {
		command(zwave.multiChannelV3.multiChannelCmdEncap(destinationEndPoint:endpoint).encapsulate(cmd))
	} else {
		command(cmd)
	}
}

private encapWithDelay(commands, endpoint, delay=200) {
	delayBetween(commands.collect{ encap(it, endpoint) }, delay)
}
