ABOUT = {
  NAME          = "L_MastervoltPV1",
  VERSION       = "0.0.1",
  DESCRIPTION   = "Device plugin for Mastervolt Soladin compatible solar inverters",
  AUTHOR        = "@vwout",
  COPYRIGHT     = "(c) 2018 Vwout",
  DOCUMENTATION = "",
  DEBUG         = false,
  LICENSE       = [[
  Copyright 2018 Vwout
  
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
]]
}

--[[
 Requires the first module listed that exists, else raises like `require`.
 If a non-string is encountered, it is returned.
 Second return value is module name loaded (or '').

 Credits: https://pastebin.com/XsP9NcVA
 --]]
local function requireany(...)
  local errs = {}
  for _,name in ipairs{...} do
    if type(name) ~= 'string' then return name, '' end
    local ok, mod = pcall(require, name)
    if ok then return mod, name end
    errs[#errs+1] = mod
  end
  error(table.concat(errs, '\n'), 2)
end

-- Try to use whatever bit-manipulation library that is available
local bit, _ = requireany('bit', 'nixio.bit', 'bit32', 'bit.numberlua')
local socket = require("socket") -- for gettime

---
-- ServiceId strings for the different sensors
-- Device ID
local PVDeviceSID          = "urn:schemas-vwout-nl:device:MastervoltPV:1"      -- Main device serviceId
-- UPnP Service IDs
local EnergyMeterSID       = "urn:micasaverde-com:serviceId:EnergyMetering1"   -- Service Id for EnergyMeter attributes
local MastervoltSID        = "urn:mastervolt-com:serviceId:MastervoltPV1"      -- Service Id for MastervoltPV attributes
local TemperatureSensorSID = "urn:upnp-org:serviceId:TemperatureSensor1"       -- Service Id for TemperatureSensor attributes
local HaDeviceSID          = "urn:micasaverde-com:serviceId:HaDevice1"         -- Service Id for HA device attributes

local Protocol = {
  Commands = {
    -- Byte sequence for Soladin commands
    PROBE           = 0xC100, -- 00 00  FF FF  C1 00  00 00  BF
    FIRMWARE        = 0xB400, -- 20 04  FF FF  B4 00  00 00  D6
    STATS           = 0xB600, -- 20 04  FF FF  B6 00  00 00  D8
    MAX_POWER       = 0xB900, -- 20 04  FF FF  B9 00  00 00  DB
    RESET_MAX_POWER = 0x9701, -- 20 04  FF FF  97 01  00 00  BA
    HISTORY         = 0x9A00  -- 20 04  FF FF  9A 00  00 00  BC
                      -- The inverter stores data (grid energy and time) for last 10 days. 
                      -- The inverter has no clock built-in, a day is therefore defined as operating season. 
                      -- The second command byte is the day to read; 0 = today, 9 = 9 days before today
  },
  CommandLength = 9,
  ReplyLength = {
    PROBE           = 9,
    FIRMWARE        = 31,
    STATS           = 31,
    MAX_POWER       = 31,
    RESET_MAX_POWER = 9,
    HISTORY         = 9
  },
  ReplyStructs = {
    Probe = {
      DeviceAddress = 0x000
    },
    Firmware = {
      Id      = 0,
      Version = 0.0,
      Date    = 0
    },
    Stats = {
      Flags                = 0x0000,
      PV_Voltage           = 0.0,
      PV_Amperage          = 0.0,
      Grid_Frequency       = 0.0,
      Grid_Voltage         = 0,
      Grid_Power           = 0,
      Grid_Output_Total    = 0,
      Device_Temperature   = 0,
      Device_Operatingtime = 0
    }
  },
  ReplyMap = { -- Indexes are lua-compliant and therefore 1-based
    Probe = {
      ADDRESS    = {3, 4}     -- Device address; actually this is the sender address present in all responses
    },
    Firmware = {
      ID         = {14, 14},
      VERSION    = {16, 17},  -- MSB is major version, LSB is minor version
      DATE       = {18, 19},
    },
    Stats = {
      FLAGS      = {7, 8},    -- Operation status flags, see Flags
      PV_VOLT    = {9, 10},   -- PV Voltage in V * 10
      PV_AMP     = {11, 12},  -- PV amperage in A * 100
      GRID_FREQ  = {13, 14},  -- Grid (output) frequency in Hz * 100
      GRID_VOLT  = {15, 16},  -- Grid (output) voltage in V
      GRID_POW   = {19, 20},  -- Grid (output) power in W
      TOTAL_POW  = {21, 23},  -- Total (cumulative)  grid power output in kWh * 100
      TEMP       = {24, 24},  -- Device operating temperature in oC
      OPTIME     = {25, 29}   -- Device operating time in minutes
     }
  },
  Flags = {
    NONE                 = 0x0000,
    USOLAR_TOO_HIGH      = 0x0001,
    USOLAR_TOO_LOW       = 0x0002,
    NO_GRID              = 0x0004,
    UAC_TOO_HIGH         = 0x0008,
    UAC_TOO_LOW          = 0x0010,
    FAC_TOO_HIGH         = 0x0020,
    FAC_TOO_LOW          = 0x0040,
    TEMPERATURE_TOO_HIGH = 0x0080,
    HARDWARE_FAILURE     = 0x0100,
    STARTING             = 0x0200,
    MAX_POWER            = 0x0400,
    MAX_CURRENT          = 0x0800
  }
}

local Config = {
  IpAddress           = "",
  IpPort              = "23",
  PollIntervalSeconds = 300,
  Debug               = true,
  AwaitingResponse    = false,
  DataBuffer          = '',
  
  Protocol = {
    DestinationAddress  = 0x2004, -- The address of the inverter - seems to be 0x0420 for my device.
    SourceAddress       = 0xFFFF  -- The source address of the host device (Vera) always uses 0xFFFF
  }
}

---
-- 'global' program variables assigned in init()
local PVDeviceID   -- Luup device ID

local function log(message)
  local devId = PVDeviceID or 'UnknownID'
  luup.log(ABOUT.NAME .. " #" .. devId .. ": " .. (message or ""))
end

local function logDbg(message)
  if Config.Debug then
    log(message)
  end
end

local function getLuupVar(name, service, device)
  service = service or PVDeviceSID
  device = device or PVDeviceID

  local x = luup.variable_get(service, name, device)
  return x
end

local function setLuupVar(name, value, service, device)
  service = service or PVDeviceSID
  device = device or PVDeviceID

  local old = getLuupVar(name, service, device)
  if tostring(value) ~= old then
    luup.variable_set(service, name, value, device)
  end
end

-- get and check UI variables
local function getDeviceVar(name, default, lower, upper, service, device)
  service = service or PVDeviceSID
  device = device or PVDeviceID
  local oldvalue = getLuupVar(name, service, device)
  local value = oldvalue or default

  if value and (value ~= "") then            -- bounds check if required
    if lower and (tonumber(value) < lower) then value = lower end
    if upper and (tonumber(value) > upper) then value = upper end
  end

  value = tostring(value)
  if value ~= oldvalue then  -- default or limits may have modified value
    setLuupVar(name, value, service, device)
  end
  return value
end

local function utils()
  local M = {}
  
  --- Return the LSB of 16-bit word
  function M.LSB(crc)
    return bit.band(crc, 0x00FF)
  end

  --- Return the MSB of 16-bit word
  function M.MSB(crc)
    return bit.rshift(crc, 8)
  end
  
  --- Returns HEX (string) representation of num
  function M.num2hex(num)
    local hexstr = '0123456789abcdef'
    local s = ''

    while num > 0 do
    local mod = math.fmod(num, 16)
    s = string.sub(hexstr, mod+1, mod+1) .. s
    num = math.floor(num / 16)
    end

    if #s == 0 then s = '0' end
    if #s == 1 then s = '0' .. s end
    return s
  end

  --- Convert string to table of bytes
  function M.str_to_arr(str, arr)
    local data = arr or {}
    if str then
    for i = 1, #str do
      data[#data + 1] = string.byte(str, i)
    end
    end
    return data
  end

  --- Convert table of bytes to string
  function M.arr_to_str(bytes, str)
    local data = str or ""
    if bytes then
    for _,v in ipairs(bytes) do
      data = data .. string.char(v)
    end
    end
    return data
  end
  
  return M
end


local utils = utils()

local function MastervoltPV_DumpRawdata(what, data)
  local s = ''

  if Config.Debug then
  if type(data) == 'string' then
      for i = 1, #data do
    s = s .. utils.num2hex(string.byte(data, i)) .. ' '
      end
    elseif type(data) == 'table' then
    for _,byte in ipairs(data) do
    s = s .. utils.num2hex(byte) .. ' '
    end
  else
    s = tostring(data)
  end
  
    log(string.format("%-40s %s", what .. ':', s))
  end
end


--- Calculate the command byte-string and send this to the inverter
--
-- The command string is a 9-bit string:
-- - b[0:1]: 16 bit destination address for the packet.
-- - b[2:3]: 16 bit source address for the packet.
-- - b[4:5]: 16 bit command ID.
-- - b[6:7]: Unknown - always 0
-- - b[8]:   Checksum
-- 
-- The first 4 bytes contain the packets source and destination. The master device (the computer) uses address 0x0000. In the probe command from the Windows software, the source and destination addresses are both set to 0x0000. This may indicate the packet is a broadcast packet intended for all non-master devices on the bus. All data is transmitted as big-endian (most significant byte first).
-- 
-- 0x00: The last byte of every packet is a checksum. It is the lower 8 bits of the sum of all the previous bytes in the packet. 
local function MastervoltPV_GetCommandStr(command, destination, source)
  local destination = destination or Config.Protocol.DestinationAddress
  local source = source or Config.Protocol.SourceAddress
  
  local cmdString = {
    utils.MSB(destination),
    utils.LSB(destination),
    utils.MSB(source),
    utils.LSB(source),
    utils.MSB(command),
    utils.LSB(command),
    0x00,
    0x00
  }
  
  local checksum = 0
  for _,byte in ipairs(cmdString) do
    checksum = checksum + byte
  end
  table.insert(cmdString, utils.LSB(checksum))

  return cmdString
end

local function MastervoltPV_SendCommand(command, destination, source)
  local commandStr = MastervoltPV_GetCommandStr(command, destination, source)
  MastervoltPV_DumpRawdata("SendCommand", commandStr)
  
  Config.AwaitingResponse = true
  return luup.io.write(utils.arr_to_str(commandStr))
end

local function MastervoltPV_GetCommandFromData(data)
  local command = 0
  
  if #data == Protocol.CommandLength then
    if type(data) == 'string' then
      command = bit.lshift(string.byte(data, 5), 8) + string.byte(data, 6)
    elseif type(data) == 'table' then
      command = bit.lshift(data[5], 8) + data[6]
    end
  end
  
  return command
end

--- Verifies the checksum (last byte) in data
local function MastervoltPV_VerifyChecksum(data)
  local checksum = -1
  local sum = 0

  if type(data) == 'string' then
    checksum = string.byte(data, -1)
    
    for i = 1, #data-1 do
      sum = sum + string.byte(data, i)
    end
  elseif type(data) == 'table' then
    local checksum = table.remove(data, -1)
     
    for _,byte in ipairs(data) do
      sum = sum + byte
    end
  end
    
  return checksum == utils.LSB(sum)
end

local function _getReplyBytes(data, bytes)
  local substr = string.sub(data, bytes[1], bytes[2])
  local value = 0

  for i = #substr, 1, -1 do
    value = bit.lshift(value, 8)
    value = value + string.byte(substr, i)
  end

  --local substr_hex = ''
  --for i = 1, #substr do
  --  substr_hex = substr_hex .. utils.num2hex(string.byte(substr, i)) .. ' '
  --end
  --logDbg(string.format("getReplyBytes %d: '%s' %d", bytes[1], substr_hex, value))
  return value
end

local function MastervoltPV_DecodeProbe(data)
  local probe = { unpack(Protocol.ReplyStructs.Probe) }
  
  address = _getReplyBytes(data, Protocol.ReplyMap.Probe.ADDRESS)
  probe.DeviceAddress = bit.lshift(utils.LSB(address), 8) + utils.MSB(address)
  
  return probe
end

local function MastervoltPV_DecodeFirmware(data)
  local firmware = { unpack(Protocol.ReplyStructs.Firmware) }
  
  firmware.Id      = _getReplyBytes(data, Protocol.ReplyMap.Firmware.ID)
  local version = _getReplyBytes(data, Protocol.ReplyMap.Firmware.VERSION)
  firmware.Version = utils.MSB(version) + utils.MSB(version) / 100
  firmware.Date    = _getReplyBytes(data, Protocol.ReplyMap.Firmware.DATE)
  
  return firmware
end

local function MastervoltPV_DecodeStats(data)
  local stats = { unpack(Protocol.ReplyStructs.Stats) }
  
  stats.Flags                = _getReplyBytes(data, Protocol.ReplyMap.Stats.FLAGS)
  stats.PV_Voltage           = _getReplyBytes(data, Protocol.ReplyMap.Stats.PV_VOLT) / 10.0
  stats.PV_Amperage          = _getReplyBytes(data, Protocol.ReplyMap.Stats.PV_AMP) / 100.0
  stats.Grid_Frequency       = _getReplyBytes(data, Protocol.ReplyMap.Stats.GRID_FREQ) / 100.0
  stats.Grid_Voltage         = _getReplyBytes(data, Protocol.ReplyMap.Stats.GRID_VOLT)
  stats.Grid_Power           = _getReplyBytes(data, Protocol.ReplyMap.Stats.GRID_POW)
  stats.Grid_Output_Total    = _getReplyBytes(data, Protocol.ReplyMap.Stats.TOTAL_POW) / 100.0
  stats.Device_Temperature   = _getReplyBytes(data, Protocol.ReplyMap.Stats.TEMP)
  stats.Device_Operatingtime = _getReplyBytes(data, Protocol.ReplyMap.Stats.OPTIME)
  
  return stats
end

local function MastervoltPV_Connect()
  local connected = false
  local ipAddress, unused, ipPort = string.match(luup.devices[lul_device].ip, "^([%w%.%-]+)(:?(%d-))$")

  if (ipAddress and ipAddress ~= "") then
    if (ipPort == '' or ipPort == nil) then
    ipPort = "23"
  end
  
  Config.IpAddress = ipAddress
  Config.IpPort    = ipPort
  
    log(string.format("Connecting to %s:%s", tostring(Config.IpAddress), tostring(Config.IpPort)))
  luup.io.open(PVDeviceID, Config.IpAddress, Config.IpPort)
  connected = true
  end
  
  return connected
end

------------------------------------------------------------------------------------

function MastervoltPV_UpdateStatus()
  luup.call_delay("MastervoltPV_UpdateStatus", Config.PollIntervalSeconds)
  
  MastervoltPV_SendCommand(Protocol.Commands.STATS)
end

-- MastervoltPV_Init() called on startup as specified in I_MastervoltPV1.xml
function MastervoltPV_Init(lul_device)
  PVDeviceID = lul_device

  log("Starting up with ID " .. luup.devices[PVDeviceID].id)
  
  Config.DataBuffer = ''
  if MastervoltPV_Connect() then
    MastervoltPV_SendCommand(Protocol.Commands.PROBE, 0x0000) -- Send probe command with destination address 0x0000
  
    Config.PollIntervalSeconds = getDeviceVar("PollIntervalSeconds", Config.PollIntervalSeconds)
    luup.call_delay("MastervoltPV_UpdateStatus", Config.PollIntervalSeconds)
  else
    return false, "Configure solar inverter IP address via Settings.", ABOUT.DESCRIPTION
  end
  
  return true
end

-- MastervoltPV_Incoming() called upon receiving of data as specified in I_MastervoltPV1.xml
function MastervoltPV_Incoming(lul_device, lul_data)
  if lul_device == PVDeviceID then
    if Config.AwaitingResponse then
      Config.DataBuffer = Config.DataBuffer .. lul_data
    else
      Config.DataBuffer = ''
    end
  end
  
  if #Config.DataBuffer > Protocol.CommandLength then
    local commandEcho = string.sub(Config.DataBuffer, 1, Protocol.CommandLength)
    local responseData = string.sub(Config.DataBuffer, Protocol.CommandLength + 1)

    MastervoltPV_DumpRawdata("Extracted command", commandEcho)
    MastervoltPV_DumpRawdata("Extracted response", responseData)

    if MastervoltPV_VerifyChecksum(commandEcho) then
      
      local command = MastervoltPV_GetCommandFromData(commandEcho)
      logDbg(string.format("Response command received: %s", utils.num2hex(command)))

      if command == Protocol.Commands.PROBE then
        if #responseData >= Protocol.ReplyLength.PROBE then
          if MastervoltPV_VerifyChecksum(responseData) then
            local probe = MastervoltPV_DecodeProbe(responseData)
            logDbg(string.format("device address': %x", probe.DeviceAddress))
            
            setLuupVar("DeviceAddress", probe.DeviceAddress, MastervoltSID) -- Store the device address as variable
            Config.Protocol.DestinationAddress = probe.DeviceAddress        -- Store the device address in the local configuration for use in all commands
          else
            logDbg("Checksum for received response failed")
          end
          
          Config.AwaitingResponse = false
          Config.DataBuffer = ''
        end
      
      
        elseif command == Protocol.Commands.FIRMWARE then
          if #responseData >= Protocol.ReplyLength.FIRMWARE then
            if MastervoltPV_VerifyChecksum(responseData) then
              local firmware = MastervoltPV_DecodeFirmware(responseData)
              logDbg(string.format("id': %x, version: %.2f, date: %d", 
                                   firmware.Id, firmware.Version, firmware.Date))
            else
              logDbg("Checksum for received response failed")
            end
            
            Config.AwaitingResponse = false
            Config.DataBuffer = ''
          end
      
      elseif command == Protocol.Commands.STATS then
        if #responseData >= Protocol.ReplyLength.STATS then
          if MastervoltPV_VerifyChecksum(responseData) then
            local stats = MastervoltPV_DecodeStats(responseData)
            logDbg(string.format("flags': %x, pv_volt: %.1f, pv_amp: %.2f, grid_freq: %.2f, grid_volt: %d, grid_pow: %d, total_pow: %.2f, temp: %d, optime: %d", 
                 stats.Flags, stats.PV_Voltage, stats.PV_Amperage, stats.Grid_Frequency, stats.Grid_Voltage, stats.Grid_Power, stats.Grid_Output_Total, stats.Device_Temperature, stats.Device_Operatingtime))
            
            setLuupVar("Flags",              stats.Flags,                  MastervoltSID)
            setLuupVar("PVVoltage",          stats.PV_Voltage,             MastervoltSID)
            setLuupVar("PVCurrent",          stats.PV_Amperage,            MastervoltSID)
            setLuupVar("GridVoltage",        stats.Grid_Voltage,           MastervoltSID)
            setLuupVar("GridFrequency",      stats.Grid_Frequency,         MastervoltSID)
            setLuupVar("OperatingTime",      stats.Device_Operatingtime,   MastervoltSID)
            setLuupVar("Watts",              stats.Grid_Power,             EnergyMeterSID)
            setLuupVar("KWH",                stats.Grid_Output_Total,      EnergyMeterSID)
            setLuupVar("CurrentTemperature", stats.Device_Temperature,     TemperatureSensorSID)
            setLuupVar("LastUpdate",         math.floor(socket.gettime()), HaDeviceSID)
          else
            logDbg("Checksum for received response failed")
          end
          
          Config.AwaitingResponse = false
          Config.DataBuffer = ''
        end
      else
        log(string.format("Unsupported response command received: %s", utils.num2hex(command)))
      
        Config.AwaitingResponse = false
        Config.DataBuffer = ''
      end
      
    else
      logDbg("Checksum for received command echo failed")
    end
  end
end


------------------------------------------------------------------------------------
-- TESTING
--
if false then
  PVDeviceID=5
  IP=""
  log("Using socket ..")

  local socket = require("socket")
  local sock = assert(socket.tcp())
  local success, err = sock:connect(IP, "23")
  if success then
    sock:settimeout(1)

    local s = ""
    
    local data = sock:receive(1)
    while data do
      s = s .. string.byte(data, 1) .. ' '
      data = sock:receive(1)
    end
    MastervoltPV_DumpRawdata("Socket data still in buffer", s)

    sock:settimeout(5)

    local commandStr = MastervoltPV_GetCommandStr(Protocol.Commands.STATS)
    MastervoltPV_DumpRawdata("SendCommand", commandStr)
    Config.AwaitingResponse = true
    local result = sock:send(utils.arr_to_str(commandStr))

    if result then
      data = sock:receive(Protocol.CommandLength + Protocol.ReplyLength.STATS)
      if data then
      MastervoltPV_Incoming(PVDeviceID, data)
      else
        logDbg("Socket no data received")
      end
    else
      logDbg("Socket send command failed")
    end
  else
    logDbg("Socket connect failed")
  end

  sock:close()
end