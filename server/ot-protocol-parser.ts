/**
 * OT/ICS Protocol Parsers
 *
 * Passive protocol analysis for industrial control system networks.
 * Parses Modbus TCP, DNP3, OPC-UA, EtherNet/IP, Profinet, BACnet,
 * IEC 61850, IEC 104, S7comm packets from captured traffic.
 *
 * IMPORTANT: These are passive parsers only — no active scanning
 * is performed on OT networks (too dangerous for production systems).
 */

// =========================================================================
// MODBUS TCP PARSER
// =========================================================================

export interface ModbusFrame {
  transactionId: number;
  protocolId: number;
  unitId: number;
  functionCode: number;
  functionName: string;
  isWrite: boolean;
  registerAddress?: number;
  registerCount?: number;
  writeValue?: string;
  readValue?: string;
  isException: boolean;
  exceptionCode?: number;
}

const MODBUS_FUNCTION_CODES: Record<number, { name: string; isWrite: boolean }> = {
  1: { name: "Read Coils", isWrite: false },
  2: { name: "Read Discrete Inputs", isWrite: false },
  3: { name: "Read Holding Registers", isWrite: false },
  4: { name: "Read Input Registers", isWrite: false },
  5: { name: "Write Single Coil", isWrite: true },
  6: { name: "Write Single Register", isWrite: true },
  7: { name: "Read Exception Status", isWrite: false },
  8: { name: "Diagnostics", isWrite: false },
  15: { name: "Write Multiple Coils", isWrite: true },
  16: { name: "Write Multiple Registers", isWrite: true },
  17: { name: "Report Server ID", isWrite: false },
  22: { name: "Mask Write Register", isWrite: true },
  23: { name: "Read/Write Multiple Registers", isWrite: true },
  43: { name: "Read Device Identification", isWrite: false },
};

export function parseModbusTcp(data: Buffer): ModbusFrame | null {
  if (data.length < 9) return null; // Minimum Modbus TCP frame

  const transactionId = data.readUInt16BE(0);
  const protocolId = data.readUInt16BE(2);
  const unitId = data.readUInt8(6);
  const functionCode = data.readUInt8(7);

  if (protocolId !== 0) return null; // Not Modbus

  const isException = functionCode > 0x80;
  const actualFc = isException ? functionCode - 0x80 : functionCode;
  const fcInfo = MODBUS_FUNCTION_CODES[actualFc] || {
    name: `Unknown (${actualFc})`,
    isWrite: false,
  };

  const frame: ModbusFrame = {
    transactionId,
    protocolId,
    unitId,
    functionCode: actualFc,
    functionName: fcInfo.name,
    isWrite: fcInfo.isWrite,
    isException,
  };

  if (isException && data.length > 8) {
    frame.exceptionCode = data.readUInt8(8);
  }

  // Parse register address and count for read/write functions
  if (!isException && data.length >= 12) {
    if ([1, 2, 3, 4, 5, 6, 15, 16].includes(actualFc)) {
      frame.registerAddress = data.readUInt16BE(8);
      if ([1, 2, 3, 4, 15, 16].includes(actualFc)) {
        frame.registerCount = data.readUInt16BE(10);
      }
      if ([5, 6].includes(actualFc)) {
        frame.writeValue = data.readUInt16BE(10).toString();
      }
    }
  }

  return frame;
}

// =========================================================================
// DNP3 PARSER
// =========================================================================

export interface Dnp3Frame {
  start: number;
  length: number;
  control: number;
  destination: number;
  source: number;
  functionCode: number;
  functionName: string;
  isWrite: boolean;
  dataObjects?: string;
}

const DNP3_FUNCTION_CODES: Record<number, { name: string; isWrite: boolean }> = {
  0: { name: "Confirm", isWrite: false },
  1: { name: "Read", isWrite: false },
  2: { name: "Write", isWrite: true },
  3: { name: "Select", isWrite: true },
  4: { name: "Operate", isWrite: true },
  5: { name: "Direct Operate", isWrite: true },
  6: { name: "Direct Operate No Ack", isWrite: true },
  7: { name: "Immediate Freeze", isWrite: true },
  8: { name: "Immediate Freeze No Ack", isWrite: true },
  9: { name: "Freeze and Clear", isWrite: true },
  10: { name: "Freeze and Clear No Ack", isWrite: true },
  13: { name: "Cold Restart", isWrite: true },
  14: { name: "Warm Restart", isWrite: true },
  15: { name: "Initialize Data", isWrite: true },
  18: { name: "Stop Application", isWrite: true },
  19: { name: "Start Application", isWrite: true },
  20: { name: "Enable Unsolicited", isWrite: true },
  21: { name: "Disable Unsolicited", isWrite: true },
  22: { name: "Assign Class", isWrite: true },
  23: { name: "Delay Measurement", isWrite: false },
  24: { name: "Record Current Time", isWrite: true },
  25: { name: "Open File", isWrite: true },
  26: { name: "Close File", isWrite: true },
  27: { name: "Delete File", isWrite: true },
  129: { name: "Response", isWrite: false },
  130: { name: "Unsolicited Response", isWrite: false },
};

export function parseDnp3(data: Buffer): Dnp3Frame | null {
  if (data.length < 10) return null;

  const start = data.readUInt16BE(0);
  if (start !== 0x0564) return null; // DNP3 start bytes

  const length = data.readUInt8(2);
  const control = data.readUInt8(3);
  const destination = data.readUInt16LE(4);
  const source = data.readUInt16LE(6);

  // Function code is in the transport/application layer
  let functionCode = 0;
  if (data.length > 12) {
    functionCode = data.readUInt8(12) & 0x7f;
  }

  const fcInfo = DNP3_FUNCTION_CODES[functionCode] || {
    name: `Unknown (${functionCode})`,
    isWrite: false,
  };

  return {
    start,
    length,
    control,
    destination,
    source,
    functionCode,
    functionName: fcInfo.name,
    isWrite: fcInfo.isWrite,
  };
}

// =========================================================================
// OPC-UA PARSER
// =========================================================================

export interface OpcUaFrame {
  messageType: string;
  chunkType: string;
  messageSize: number;
  secureChannelId?: number;
  serviceNodeId?: number;
  serviceName: string;
  isWrite: boolean;
}

const OPC_UA_SERVICE_NODES: Record<number, { name: string; isWrite: boolean }> = {
  426: { name: "ReadRequest", isWrite: false },
  429: { name: "ReadResponse", isWrite: false },
  671: { name: "WriteRequest", isWrite: true },
  674: { name: "WriteResponse", isWrite: true },
  461: { name: "CreateSubscriptionRequest", isWrite: false },
  464: { name: "CreateSubscriptionResponse", isWrite: false },
  769: { name: "BrowseRequest", isWrite: false },
  772: { name: "BrowseResponse", isWrite: false },
  527: { name: "PublishRequest", isWrite: false },
  530: { name: "PublishResponse", isWrite: false },
  446: { name: "CreateSessionRequest", isWrite: false },
  449: { name: "CreateSessionResponse", isWrite: false },
  452: { name: "ActivateSessionRequest", isWrite: false },
  455: { name: "ActivateSessionResponse", isWrite: false },
  473: { name: "CloseSessionRequest", isWrite: false },
  476: { name: "CloseSessionResponse", isWrite: false },
  631: { name: "CallRequest", isWrite: true },
  634: { name: "CallResponse", isWrite: true },
};

export function parseOpcUa(data: Buffer): OpcUaFrame | null {
  if (data.length < 8) return null;

  const msgTypeBytes = data.subarray(0, 3).toString("ascii");
  const validTypes = ["HEL", "ACK", "OPN", "CLO", "MSG", "ERR"];
  if (!validTypes.includes(msgTypeBytes)) return null;

  const chunkType = String.fromCharCode(data.readUInt8(3));
  const messageSize = data.readUInt32LE(4);

  let secureChannelId: number | undefined;
  let serviceNodeId: number | undefined;
  let serviceName = msgTypeBytes;
  let isWrite = false;

  if (msgTypeBytes === "MSG" && data.length >= 16) {
    secureChannelId = data.readUInt32LE(8);

    // Try to extract service node ID from the message body
    if (data.length >= 26) {
      // The service node ID location varies, but typically around offset 24-26
      const possibleNodeId = data.readUInt16LE(24);
      if (OPC_UA_SERVICE_NODES[possibleNodeId]) {
        serviceNodeId = possibleNodeId;
        const svcInfo = OPC_UA_SERVICE_NODES[possibleNodeId];
        serviceName = svcInfo.name;
        isWrite = svcInfo.isWrite;
      }
    }
  }

  return {
    messageType: msgTypeBytes,
    chunkType,
    messageSize,
    secureChannelId,
    serviceNodeId,
    serviceName,
    isWrite,
  };
}

// =========================================================================
// ETHERNET/IP PARSER
// =========================================================================

export interface EthernetIpFrame {
  command: number;
  commandName: string;
  length: number;
  sessionHandle: number;
  status: number;
  isWrite: boolean;
}

const ENIP_COMMANDS: Record<number, { name: string; isWrite: boolean }> = {
  0x0001: { name: "ListServices", isWrite: false },
  0x0004: { name: "ListIdentity", isWrite: false },
  0x0063: { name: "ListInterfaces", isWrite: false },
  0x0065: { name: "RegisterSession", isWrite: false },
  0x0066: { name: "UnregisterSession", isWrite: false },
  0x006f: { name: "SendRRData", isWrite: false },
  0x0070: { name: "SendUnitData", isWrite: true },
};

export function parseEthernetIp(data: Buffer): EthernetIpFrame | null {
  if (data.length < 24) return null; // EtherNet/IP header is 24 bytes

  const command = data.readUInt16LE(0);
  const length = data.readUInt16LE(2);
  const sessionHandle = data.readUInt32LE(4);
  const status = data.readUInt32LE(8);

  const cmdInfo = ENIP_COMMANDS[command] || {
    name: `Unknown (0x${command.toString(16)})`,
    isWrite: false,
  };

  return {
    command,
    commandName: cmdInfo.name,
    length,
    sessionHandle,
    status,
    isWrite: cmdInfo.isWrite,
  };
}

// =========================================================================
// PROFINET PARSER
// =========================================================================

export interface ProfinetFrame {
  frameId: number;
  frameType: string;
  isWrite: boolean;
  cycleCounter?: number;
  dataStatus?: number;
}

export function parseProfinet(data: Buffer): ProfinetFrame | null {
  if (data.length < 4) return null;

  const frameId = data.readUInt16BE(0);

  let frameType: string;
  let isWrite = false;

  if (frameId >= 0x0100 && frameId <= 0x7fff) {
    frameType = "RT_CLASS_1_CYCLIC"; // Real-time cyclic data
  } else if (frameId >= 0x8000 && frameId <= 0xbfff) {
    frameType = "RT_CLASS_2_CYCLIC";
  } else if (frameId >= 0xc000 && frameId <= 0xfbff) {
    frameType = "RT_CLASS_3_CYCLIC";
  } else if (frameId === 0xfc01) {
    frameType = "ALARM_HIGH";
    isWrite = true;
  } else if (frameId === 0xfe01) {
    frameType = "ALARM_LOW";
    isWrite = true;
  } else if (frameId === 0xfefe) {
    frameType = "DCP_HELLO";
  } else if (frameId === 0xfefd) {
    frameType = "DCP_GET_SET";
    isWrite = true;
  } else if (frameId === 0xfefc) {
    frameType = "DCP_IDENTIFY_REQ";
  } else if (frameId === 0xfefb) {
    frameType = "DCP_IDENTIFY_RES";
  } else {
    frameType = `UNKNOWN_0x${frameId.toString(16)}`;
  }

  const frame: ProfinetFrame = { frameId, frameType, isWrite };

  if (data.length >= 6) {
    frame.cycleCounter = data.readUInt16BE(2);
    frame.dataStatus = data.readUInt8(4);
  }

  return frame;
}

// =========================================================================
// S7COMM PARSER (Siemens S7)
// =========================================================================

export interface S7CommFrame {
  protocolId: number;
  messageType: number;
  messageTypeName: string;
  functionCode: number;
  functionName: string;
  isWrite: boolean;
  parameterLength: number;
  dataLength: number;
}

const S7_MESSAGE_TYPES: Record<number, string> = {
  0x01: "Job Request",
  0x02: "Ack",
  0x03: "Ack Data",
  0x07: "Userdata",
};

const S7_FUNCTION_CODES: Record<number, { name: string; isWrite: boolean }> = {
  0x00: { name: "CPU Services", isWrite: false },
  0x04: { name: "Read Var", isWrite: false },
  0x05: { name: "Write Var", isWrite: true },
  0x1a: { name: "Request Download", isWrite: true },
  0x1b: { name: "Download Block", isWrite: true },
  0x1c: { name: "Download Ended", isWrite: true },
  0x1d: { name: "Start Upload", isWrite: false },
  0x1e: { name: "Upload", isWrite: false },
  0x1f: { name: "End Upload", isWrite: false },
  0x28: { name: "PLC Control", isWrite: true },
  0x29: { name: "PLC Stop", isWrite: true },
  0xf0: { name: "Setup Communication", isWrite: false },
};

export function parseS7Comm(data: Buffer): S7CommFrame | null {
  if (data.length < 10) return null;

  const protocolId = data.readUInt8(0);
  if (protocolId !== 0x32) return null; // S7comm protocol marker

  const messageType = data.readUInt8(1);
  const parameterLength = data.readUInt16BE(6);
  const dataLength = data.readUInt16BE(8);

  let functionCode = 0;
  if (data.length > 10) {
    functionCode = data.readUInt8(10);
  }

  const fcInfo = S7_FUNCTION_CODES[functionCode] || {
    name: `Unknown (0x${functionCode.toString(16)})`,
    isWrite: false,
  };

  return {
    protocolId,
    messageType,
    messageTypeName: S7_MESSAGE_TYPES[messageType] || `Unknown (0x${messageType.toString(16)})`,
    functionCode,
    functionName: fcInfo.name,
    isWrite: fcInfo.isWrite,
    parameterLength,
    dataLength,
  };
}

// =========================================================================
// ICS-CERT ADVISORY SIGNATURES
// =========================================================================

export interface IcsThreatSignature {
  id: string;
  name: string;
  description: string;
  protocol: string;
  severity: "critical" | "high" | "medium" | "low";
  mitreTactic: string;
  mitreTechnique: string;
  icsCertAdvisory?: string;
  matchFn: (frame: ParsedProtocolFrame) => boolean;
}

export type ParsedProtocolFrame =
  | { protocol: "modbus_tcp"; frame: ModbusFrame }
  | { protocol: "dnp3"; frame: Dnp3Frame }
  | { protocol: "opc_ua"; frame: OpcUaFrame }
  | { protocol: "ethernet_ip"; frame: EthernetIpFrame }
  | { protocol: "profinet"; frame: ProfinetFrame }
  | { protocol: "s7comm"; frame: S7CommFrame };

export const OT_THREAT_SIGNATURES: IcsThreatSignature[] = [
  // PLC Stop/Restart attacks
  {
    id: "OT-SIG-001",
    name: "PLC Stop Command Detected",
    description: "A PLC stop command was issued, which could halt industrial processes",
    protocol: "s7comm",
    severity: "critical",
    mitreTactic: "Inhibit Response Function",
    mitreTechnique: "T0816 - Device Restart/Shutdown",
    matchFn: (p) => p.protocol === "s7comm" && p.frame.functionCode === 0x29,
  },
  {
    id: "OT-SIG-002",
    name: "PLC Cold Restart via DNP3",
    description: "A cold restart command was sent via DNP3, resetting the device completely",
    protocol: "dnp3",
    severity: "critical",
    mitreTactic: "Inhibit Response Function",
    mitreTechnique: "T0816 - Device Restart/Shutdown",
    matchFn: (p) => p.protocol === "dnp3" && p.frame.functionCode === 13,
  },
  // Ladder logic / firmware manipulation
  {
    id: "OT-SIG-003",
    name: "PLC Program Download Detected",
    description: "A program download to PLC was detected — possible ladder logic manipulation",
    protocol: "s7comm",
    severity: "critical",
    mitreTactic: "Impair Process Control",
    mitreTechnique: "T0843 - Program Download",
    matchFn: (p) => p.protocol === "s7comm" && [0x1a, 0x1b, 0x1c].includes(p.frame.functionCode),
  },
  // Unauthorized write operations
  {
    id: "OT-SIG-004",
    name: "Modbus Write to Coils",
    description: "Write operation to Modbus coils — could alter physical actuator states",
    protocol: "modbus_tcp",
    severity: "high",
    mitreTactic: "Impair Process Control",
    mitreTechnique: "T0855 - Unauthorized Command Message",
    matchFn: (p) => p.protocol === "modbus_tcp" && [5, 15].includes(p.frame.functionCode),
  },
  {
    id: "OT-SIG-005",
    name: "Modbus Write to Holding Registers",
    description: "Write to holding registers detected — potential setpoint change",
    protocol: "modbus_tcp",
    severity: "high",
    mitreTactic: "Impair Process Control",
    mitreTechnique: "T0836 - Modify Parameter",
    matchFn: (p) => p.protocol === "modbus_tcp" && [6, 16].includes(p.frame.functionCode),
  },
  // DNP3 Direct Operate (no confirmation)
  {
    id: "OT-SIG-006",
    name: "DNP3 Direct Operate No Ack",
    description: "DNP3 Direct Operate without acknowledgment — unconfirmed control action",
    protocol: "dnp3",
    severity: "high",
    mitreTactic: "Impair Process Control",
    mitreTechnique: "T0855 - Unauthorized Command Message",
    matchFn: (p) => p.protocol === "dnp3" && p.frame.functionCode === 6,
  },
  // OPC-UA Write
  {
    id: "OT-SIG-007",
    name: "OPC-UA Write Request",
    description: "OPC-UA write request detected — data modification on OT device",
    protocol: "opc_ua",
    severity: "high",
    mitreTactic: "Impair Process Control",
    mitreTechnique: "T0836 - Modify Parameter",
    matchFn: (p) => p.protocol === "opc_ua" && p.frame.isWrite,
  },
  // Safety system bypass
  {
    id: "OT-SIG-008",
    name: "Safety System Communication Detected",
    description: "Write command to safety instrumented system — potential SIS bypass attempt",
    protocol: "modbus_tcp",
    severity: "critical",
    mitreTactic: "Inhibit Response Function",
    mitreTechnique: "T0800 - Activate Firmware Update Mode",
    icsCertAdvisory: "ICSA-GENERIC-SIS",
    matchFn: (p) =>
      p.protocol === "modbus_tcp" && p.frame.isWrite && p.frame.unitId !== undefined && p.frame.unitId >= 200,
  },
  // Network reconnaissance
  {
    id: "OT-SIG-009",
    name: "Modbus Device Identification Scan",
    description: "Device identification request — likely reconnaissance activity",
    protocol: "modbus_tcp",
    severity: "medium",
    mitreTactic: "Discovery",
    mitreTechnique: "T0846 - Remote System Discovery",
    matchFn: (p) => p.protocol === "modbus_tcp" && p.frame.functionCode === 43,
  },
  // Profinet alarms
  {
    id: "OT-SIG-010",
    name: "Profinet High Priority Alarm",
    description: "High priority alarm on Profinet network — potential safety concern",
    protocol: "profinet",
    severity: "high",
    mitreTactic: "Impair Process Control",
    mitreTechnique: "T0831 - Manipulation of Control",
    matchFn: (p) => p.protocol === "profinet" && p.frame.frameType === "ALARM_HIGH",
  },
  // DNP3 file operations (potential firmware manipulation)
  {
    id: "OT-SIG-011",
    name: "DNP3 File Operation",
    description: "File open/close/delete operation via DNP3 — possible firmware manipulation",
    protocol: "dnp3",
    severity: "critical",
    mitreTactic: "Impair Process Control",
    mitreTechnique: "T0839 - Module Firmware",
    matchFn: (p) => p.protocol === "dnp3" && [25, 26, 27].includes(p.frame.functionCode),
  },
  // S7 PLC Control command
  {
    id: "OT-SIG-012",
    name: "S7 PLC Control Command",
    description: "PLC control command via S7comm — direct manipulation of PLC state",
    protocol: "s7comm",
    severity: "critical",
    mitreTactic: "Impair Process Control",
    mitreTechnique: "T0855 - Unauthorized Command Message",
    matchFn: (p) => p.protocol === "s7comm" && p.frame.functionCode === 0x28,
  },
  // Modbus exception (could indicate fuzzing or attack)
  {
    id: "OT-SIG-013",
    name: "Modbus Exception Response",
    description: "Modbus device returned an exception — could indicate protocol fuzzing",
    protocol: "modbus_tcp",
    severity: "medium",
    mitreTactic: "Discovery",
    mitreTechnique: "T0846 - Remote System Discovery",
    matchFn: (p) => p.protocol === "modbus_tcp" && p.frame.isException,
  },
  // Profinet DCP Set (device configuration change)
  {
    id: "OT-SIG-014",
    name: "Profinet DCP Configuration Change",
    description: "DCP Get/Set operation detected — device configuration modification",
    protocol: "profinet",
    severity: "high",
    mitreTactic: "Impair Process Control",
    mitreTechnique: "T0836 - Modify Parameter",
    matchFn: (p) => p.protocol === "profinet" && p.frame.frameType === "DCP_GET_SET",
  },
  // EtherNet/IP data transfer
  {
    id: "OT-SIG-015",
    name: "EtherNet/IP Unit Data Transfer",
    description: "Unit data transfer via EtherNet/IP — I/O data exchange with controller",
    protocol: "ethernet_ip",
    severity: "medium",
    mitreTactic: "Collection",
    mitreTechnique: "T0801 - Monitor Process State",
    matchFn: (p) => p.protocol === "ethernet_ip" && p.frame.command === 0x0070,
  },
];

/**
 * Match a parsed protocol frame against all OT threat signatures.
 * Returns matched signatures (can be multiple).
 */
export function matchThreatSignatures(parsed: ParsedProtocolFrame): IcsThreatSignature[] {
  return OT_THREAT_SIGNATURES.filter((sig) => {
    try {
      return sig.matchFn(parsed);
    } catch {
      return false;
    }
  });
}

// =========================================================================
// PURDUE MODEL CLASSIFICATION
// =========================================================================

export interface PurdueClassification {
  level: string;
  levelName: string;
  description: string;
}

const PURDUE_MODEL: Record<string, PurdueClassification> = {
  level_0: {
    level: "level_0",
    levelName: "Physical Process",
    description: "Sensors, actuators, physical devices that interact with the industrial process",
  },
  level_1: {
    level: "level_1",
    levelName: "Basic Control",
    description: "PLCs, RTUs, safety systems — direct control of the physical process",
  },
  level_2: {
    level: "level_2",
    levelName: "Area Supervisory",
    description: "HMIs, SCADA servers, engineering workstations — operator interface and local control",
  },
  level_3: {
    level: "level_3",
    levelName: "Site Operations",
    description: "Historians, MES, batch management — site-wide operations and manufacturing",
  },
  level_3_5: {
    level: "level_3_5",
    levelName: "IT/OT DMZ",
    description: "Firewalls, jump hosts, data diodes — demilitarized zone between IT and OT",
  },
  level_4: {
    level: "level_4",
    levelName: "Enterprise IT",
    description: "ERP, email, business systems — enterprise network resources",
  },
  level_5: {
    level: "level_5",
    levelName: "Enterprise Network / Internet",
    description: "Internet-facing systems, cloud services, remote access",
  },
};

export function getPurdueLevel(level: string): PurdueClassification | null {
  return PURDUE_MODEL[level] || null;
}

export function getAllPurdueLevels(): PurdueClassification[] {
  return Object.values(PURDUE_MODEL);
}

/**
 * Classify an OT asset into a Purdue level based on its type.
 */
export function classifyAssetPurdueLevel(assetType: string): string {
  switch (assetType) {
    case "sensor":
    case "actuator":
    case "meter":
    case "relay":
      return "level_0";
    case "plc":
    case "rtu":
    case "dcs":
    case "safety_system":
      return "level_1";
    case "hmi":
    case "scada_server":
    case "engineering_workstation":
      return "level_2";
    case "historian":
      return "level_3";
    case "firewall":
    case "gateway":
      return "level_3_5";
    case "network_switch":
      return "level_2"; // Switches can be at multiple levels, default to L2
    case "drive":
    case "robot":
      return "level_1";
    default:
      return "level_2";
  }
}

// =========================================================================
// IT/OT BOUNDARY DETECTION
// =========================================================================

/**
 * Determine if a connection crosses the IT/OT boundary (Purdue Level 3.5).
 * Any traffic between Level <= 3 and Level >= 4 crosses the boundary.
 */
export function crossesBoundary(sourcePurdueLevel: string, destPurdueLevel: string): boolean {
  const LEVEL_VALUES: Record<string, number> = {
    level_0: 0,
    level_1: 1,
    level_2: 2,
    level_3: 3,
    level_3_5: 3.5,
    level_4: 4,
    level_5: 5,
  };

  const srcLevel = LEVEL_VALUES[sourcePurdueLevel];
  const dstLevel = LEVEL_VALUES[destPurdueLevel];

  if (srcLevel === undefined || dstLevel === undefined) return false;

  // Crosses boundary if one side is OT (<=3) and the other is IT (>=4)
  const srcIsOt = srcLevel <= 3;
  const dstIsOt = dstLevel <= 3;

  return srcIsOt !== dstIsOt;
}
