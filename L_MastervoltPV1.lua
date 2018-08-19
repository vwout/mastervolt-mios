--[==[
  Module L_MastervoltPV1.lua
  Written by Vwout

  V0.1 First release

  Get data from Mastervolt Soladin-compatible Solar inverted
--]==]
local ABOUT = {
  NAME          = "L_MastervoltPV1",
  VERSION       = "0.1",
  DESCRIPTION   = "Device plugin for Mastervolt Soladin compatible solar inverters",
  AUTHOR        = "@vwout",
  COPYRIGHT     = "(c) 2018 Vwout",
  DOCUMENTATION = "",
  DEBUG         = true,
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
 Second return value is module name loaded (or "").

 Credits: https://pastebin.com/XsP9NcVA
 --]]
local function requireany(...)
  local errs = {}
  for _,name in ipairs{...} do
    if type(name) ~= "string" then return name, "" end
    local ok, mod = pcall(require, name)
    if ok then return mod, name end
    errs[#errs + 1] = mod
  end
  error(table.concat(errs, "\n"), 2)
end

--- Imports
-- Try to use whatever bit-manipulation library that is available
local bit, _ = requireany("bit", "nixio.bit", "bit32", "bit.numberlua")
local socket = require("socket") -- for gettime


---
-- ServiceId strings for the different sensors
-- Device ID
local PVDeviceSID          = "urn:schemas-vwout-nl:device:MastervoltPV:1"      -- Main device serviceId
-- UPnP Service IDs for storing attributes at the appropriate service
local EnergyMeterSID       = "urn:micasaverde-com:serviceId:EnergyMetering1"
local MastervoltSID        = "urn:mastervolt-com:serviceId:MastervoltPV1"
local TemperatureSensorSID = "urn:upnp-org:serviceId:TemperatureSensor1"
local HaDeviceSID          = "urn:micasaverde-com:serviceId:HaDevice1"

local Protocol = {
  Commands = {
    -- Byte sequence for Soladin commands
    PROBE           = 0x00C1, -- 00 00  FF FF  C1 00  00 00  xx
    FIRMWARE        = 0x00B4, -- xx xx  FF FF  B4 00  00 00  xx
    STATS           = 0x00B6, -- xx xx  FF FF  B6 00  00 00  xx
    MAX_POWER       = 0x00B9, -- xx xx  FF FF  B9 00  00 00  xx
    RESET_MAX_POWER = 0x0197, -- xx xx  FF FF  97 01  00 00  xx
    HISTORY         = 0x009A  -- xx xx  FF FF  9A 00  00 00  xx
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
  ReplyMap = { -- Indexes are lua-compliant and therefore 1-based
    Probe = {
      DeviceAddress        = {3, 4}     -- Device address; actually this is the sender address present in all responses
    },
    Firmware = {
      Id                   = {14, 14},
      MinorVersion         = {16, 16},  -- minor version (LSB of version)
      MajorVersion         = {17, 17},  -- major version,(MSB of version)
      Date                 = {18, 19}
    },
    Stats = {
      Flags                = {7, 8},    -- Operation status flags, see Flags
      PV_Voltage           = {9, 10},   -- PV Voltage in V * 10
      PV_Amperage          = {11, 12},  -- PV amperage in A * 100
      Grid_Frequency       = {13, 14},  -- Grid (output) frequency in Hz * 100
      Grid_Voltage         = {15, 16},  -- Grid (output) voltage in V
      Grid_Power           = {19, 20},  -- Grid (output) power in W
      Grid_Output_Total    = {21, 23},  -- Total (cumulative)  grid power output in kWh * 100
      Device_Temperature   = {24, 24},  -- Device operating temperature in degrees Celsius
      Device_Operatingtime = {25, 29}   -- Device operating time in minutes
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
  PVDeviceID          = nil,      -- Luup device ID, assigned in init()
  IpAddress           = "",
  IpPort              = "23",
  PollIntervalSeconds = 300,
  Debug               = ABOUT.DEBUG,
  AwaitingResponse    = false,
  DataBuffer          = "",

  Protocol = {
    DestinationAddress  = 0x0000, -- The address of the inverter - filled after a PROBE response
    SourceAddress       = 0xFFFF  -- The source address of the host device (Vera) - always uses 0xFFFF
  }
}

local function log(message)
  local devId = tostring(Config.PVDeviceID) or "UnknownID"
  luup.log(ABOUT.NAME .. " #" .. devId .. ": " .. (message or ""))
end

local function logDbg(message)
  if Config.Debug then
    log(message)
  end
end

local function getLuupVar(name, service, device)
  service = service or PVDeviceSID
  device = device or Config.PVDeviceID

  local x = luup.variable_get(service, name, device)
  return x
end

local function setLuupVar(name, value, service, device)
  service = service or PVDeviceSID
  device = device or Config.PVDeviceID

  local old = getLuupVar(name, service, device)
  if tostring(value) ~= old then
    luup.variable_set(service, name, value, device)
  end
end

-- get and check UI variables
local function getDeviceVar(name, default, lower, upper, service, device)
  service = service or PVDeviceSID
  device = device or Config.PVDeviceID
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

local function Utils()
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
    local hexstr = "0123456789abcdef"
    local s = ""

    while num > 0 do
    local mod = math.fmod(num, 16)
    s = string.sub(hexstr, mod + 1, mod + 1) .. s
    num = math.floor(num / 16)
    end

    if #s == 0 then s = "0" end
    if #s == 1 then s = "0" .. s end
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

-- Make Utils instance globally available for all functions to use
local utils = Utils()

local function MastervoltPV_DumpRawdata(what, data)
  local s = ""

  if Config.Debug then
    if type(data) == "string" then
      for i = 1, #data do
          s = s .. utils.num2hex(string.byte(data, i)) .. " "
      end
    elseif type(data) == "table" then
      for _,byte in ipairs(data) do
        s = s .. utils.num2hex(byte) .. " "
      end
    else
      s = tostring(data)
    end

    logDbg(string.format("%-40s %s", what .. ":", s))
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
-- The first 4 bytes contain the packets source and destination. The master device (the computer) uses address 0x0000.
-- In the probe command from the Windows software, the source and destination addresses are both set to 0x0000.
-- This may indicate the packet is a broadcast packet intended for all non-master devices on the bus.
-- All data is transmitted as little-endian (least significant byte first).
--
-- The last byte of every packet is a checksum.
-- It is the lower 8 bits of the sum of all the previous bytes in the packet.
local function MastervoltPV_GetCommandStr(command, destination, source)
  local dest_addr = destination or Config.Protocol.DestinationAddress
  local source_addr = source or Config.Protocol.SourceAddress

  local cmdString = {
    utils.LSB(dest_addr),
    utils.MSB(dest_addr),
    utils.LSB(source_addr),
    utils.MSB(source_addr),
    utils.LSB(command),
    utils.MSB(command),
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
  local commandName = nil

  -- Reverse bytes to convert from little-endian
  if #data == Protocol.CommandLength then
    if type(data) == "string" then
      command = bit.lshift(string.byte(data, 6), 8) + string.byte(data, 5)
    elseif type(data) == "table" then
      command = bit.lshift(data[6], 8) + data[5]
    end
  end

  for key, value in pairs(Protocol.Commands) do
    if value == command then
      commandName = key
      break
    end
  end

  return command, commandName
end

--- Verifies the checksum in data
--
-- The last byte of every packet is a checksum.
-- It is the lower 8 bits of the sum of all the previous bytes in the packet.
--
local function MastervoltPV_VerifyChecksum(data)
  local checksum = -1
  local sum = 0

  if type(data) == "string" then
    checksum = string.byte(data, -1)

    for i = 1, #data-1 do
      sum = sum + string.byte(data, i)
    end
  elseif type(data) == "table" then
    checksum = table.remove(data, -1)

    for _,byte in ipairs(data) do
      sum = sum + byte
    end
  end

  return checksum == utils.LSB(sum)
end

--- Retrieve a subset of data, indicate by the byte index provided in the bytes array argument
--
-- When the bytes array has only 1 entry, only 1 byte is used
local function _getReplyBytes(data, bytes)
  local substr = string.sub(data, bytes[1], bytes[2] or bytes[1])
  local value = 0

  -- Data is transmitted little-endian, reverse the bytes
  for i = #substr, 1, -1 do
    value = bit.lshift(value, 8)
    value = value + string.byte(substr, i)
  end

  return value
end

--- Decode the response by using the Protocol ReplyMap for the response
--
-- The replymap is map with pairs of the attribute name and the byte(s) that
-- contain the atribute values.
-- The result is an array with pairs of the attribute name with the value
-- obtained from the response data.
local function MastervoltPV_DecodeResponse(data, structure)
  local values = {}

  for key, value in pairs(structure) do
    values[key] = _getReplyBytes(data, value)
  end

  return values
end

local function MastervoltPV_HandleIncomingProbe(responseData)
  local probe = MastervoltPV_DecodeResponse(responseData, Protocol.ReplyMap.Probe)
  logDbg(string.format("Device address: %s", utils.num2hex(probe.DeviceAddress)))

  -- Store the device address as variable
  setLuupVar("DeviceAddress", probe.DeviceAddress, MastervoltSID)

  -- Store the device address in the local configuration for use in all commands
  Config.Protocol.DestinationAddress = probe.DeviceAddress

  return probe
end

local function MastervoltPV_HandleIncomingFirmware(responseData)
  local firmware = MastervoltPV_DecodeResponse(responseData, Protocol.ReplyMap.Firmware)
  logDbg(string.format("id: %x, version: %02d.%02d, date: %d",
         firmware.Id, firmware.MajorVersion, firmware.MinorVersion, firmware.Date))

  return firmware
end

local function MastervoltPV_HandleIncomingStats(responseData)
  local stats = MastervoltPV_DecodeResponse(responseData, Protocol.ReplyMap.Stats)
  logDbg(string.format("flags: %x, pv_volt: %.1f, pv_amp: %.2f, " ..
                       "grid_freq: %.2f, grid_volt: %d, grid_pow: %d, total_pow: %.2f, " ..
                       "temp: %d, optime: %d",
         stats.Flags, stats.PV_Voltage / 10.0, stats.PV_Amperage / 100.0,
         stats.Grid_Frequency / 100.0, stats.Grid_Voltage, stats.Grid_Power, stats.Grid_Output_Total / 100.0,
         stats.Device_Temperature, stats.Device_Operatingtime))

  setLuupVar("Flags",              stats.Flags,                     MastervoltSID)
  setLuupVar("PVVoltage",          stats.PV_Voltage / 10.0,         MastervoltSID)
  setLuupVar("PVCurrent",          stats.PV_Amperage / 100.0,       MastervoltSID)
  setLuupVar("GridVoltage",        stats.Grid_Voltage,              MastervoltSID)
  setLuupVar("GridFrequency",      stats.Grid_Frequency / 100.0,    MastervoltSID)
  setLuupVar("OperatingTime",      stats.Device_Operatingtime,      MastervoltSID)
  setLuupVar("Watts",              stats.Grid_Power,                EnergyMeterSID)
  setLuupVar("KWH",                stats.Grid_Output_Total / 100.0, EnergyMeterSID)
  setLuupVar("CurrentTemperature", stats.Device_Temperature,        TemperatureSensorSID)
  setLuupVar("LastUpdate",         math.floor(socket.gettime()),    HaDeviceSID)

  return stats
end

-- Array to map a command to a corresponding incoming data handle function
local HandleIncomingFuncMap = {
  [Protocol.Commands.PROBE]    = MastervoltPV_HandleIncomingProbe,
  [Protocol.Commands.FIRMWARE] = MastervoltPV_HandleIncomingFirmware,
  [Protocol.Commands.STATS]    = MastervoltPV_HandleIncomingStats
}


local function MastervoltPV_Connect()
  local connected = false
  local ip = luup.devices[Config.PVDeviceID].ip or ""

  if (ip == "") then
    log("IP-address not configured. Assuming running using serial connection.")
  else
    local ipAddress, _, ipPort = string.match(ip, "^([%w%.%-]+)(:?(%d-))$")

    if (ipAddress and ipAddress ~= "") then
      if (ipPort == "" or ipPort == nil) then
        ipPort = "23"
      end

      Config.IpAddress = tostring(ipAddress)
      Config.IpPort    = tostring(ipPort)

      logDbg(string.format("Connecting to %s:%s", Config.IpAddress, Config.IpPort))
      luup.io.open(Config.PVDeviceID, Config.IpAddress, Config.IpPort)
      connected = true
    end
  end

  return connected
end

------------------------------------------------------------------------------------

function MastervoltPV_UpdateDeviceAddress()
    MastervoltPV_SendCommand(Protocol.Commands.PROBE, 0x0000) -- Send probe command with destination address 0x0000
end

function MastervoltPV_UpdateStatus()
  luup.call_delay("MastervoltPV_UpdateStatus", Config.PollIntervalSeconds)

  MastervoltPV_SendCommand(Protocol.Commands.STATS)
end

-- MastervoltPV_Init() called on startup as specified in I_MastervoltPV1.xml
function MastervoltPV_Init(lul_device)
  Config.PVDeviceID = lul_device

  log("Starting up with ID " .. tostring(luup.devices[Config.PVDeviceID].id))

  Config.DataBuffer = ""
  Config.AwaitingResponse = false

  if MastervoltPV_Connect() then

    Config.PollIntervalSeconds         = getDeviceVar("PollIntervalSeconds",
                                                      Config.PollIntervalSeconds, 5, 3600)
    Config.Protocol.DestinationAddress = getDeviceVar("DeviceAddress",
                                                      tostring(Config.Protocol.DestinationAddress),
                                                      0x0000, 0xFFFF, MastervoltSID)

    -- Call with a small delay to allow Luup to initialize
    luup.call_delay("MastervoltPV_UpdateDeviceAddress", 5)
    luup.call_delay("MastervoltPV_UpdateStatus",        Config.PollIntervalSeconds + 10)
  else
    return false, "Configure solar inverter IP address via Settings.", ABOUT.NAME
  end

  return true, "Connected to inverter", ABOUT.NAME
end

-- MastervoltPV_Incoming() called upon receiving of data as specified in I_MastervoltPV1.xml
function MastervoltPV_Incoming(lul_device, lul_data)
  if lul_device == Config.PVDeviceID then
    if Config.AwaitingResponse then
      Config.DataBuffer = Config.DataBuffer .. lul_data
    else
      Config.DataBuffer = ""
    end
  end

  if #Config.DataBuffer > Protocol.CommandLength then
    local commandEcho = string.sub(Config.DataBuffer, 1, Protocol.CommandLength)
    local responseData = string.sub(Config.DataBuffer, Protocol.CommandLength + 1)

    MastervoltPV_DumpRawdata("Extracted command", commandEcho)
    MastervoltPV_DumpRawdata("Extracted response", responseData)

    if MastervoltPV_VerifyChecksum(commandEcho) then

      local handledOrUnsupported = false
      local command, commandName = MastervoltPV_GetCommandFromData(commandEcho)
      logDbg(string.format("Response command received: %s (%s)",
             utils.num2hex(command), commandName or "<unknown command>"))

      if commandName then
        local handleFunc = HandleIncomingFuncMap[command]
        if handleFunc then
          if #responseData >= Protocol.ReplyLength[commandName] then
            if MastervoltPV_VerifyChecksum(responseData) then
              handleFunc(responseData)
            else
              logDbg("Checksum for received response failed")
            end

            handledOrUnsupported = true
          end
        else
          log(string.format("Unsupported response command received: %s", utils.num2hex(command)))
          handledOrUnsupported = true
        end
      else
        handledOrUnsupported = true
      end

      if handledOrUnsupported then
        Config.AwaitingResponse = false
        Config.DataBuffer = ""
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
  Config.PVDeviceID = 5
  local IP = ""
  log("Using socket ..")

  local sock = assert(socket.tcp())
  local success,_ = sock:connect(IP, "23")
  if success then
    sock:settimeout(1)

    local s = ""

    local data = sock:receive(1)
    while data do
      s = s .. string.byte(data, 1) .. " "
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
      MastervoltPV_Incoming(Config.PVDeviceID, data)
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
