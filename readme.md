# Mastervolt-PV
A [Vera](http://getvera.com/) plugin for Soladin/Mastervolt PV inverters to read solar production data.

## Plugin
This plugin connects via a serial or telnet connection to the invertor (see below). Multiple devices can be created in case more than one inverter is installed. The plugin will only read the statistics on the current PV inverter status. The following data is recorded:
- PV panel voltage
- PV panel current
- Grid (output) frequency
- Grid (output) voltage
- Grid (output) power (W)
- Total (cumulative) grid power output (kWh)
- Inverter operating temperature
- Total device operating time

## Connection
The Mastervolt inverter is a small grid connected inverter sold in Europe. It features a serial port that when combined with a small adapter can connect the inverter to a computer for monitoring the power levels and status of the device. Although Mastervolt describes the interface as RS485, it is not compatible with it. An RS232 adapter named PC-link can be purchased from Mastervolt for connection to a PC. Communication runs at 9,600 bps with 8 data bits and no parity. A convenient way to connect the interter to the Vera is either by using a direct connection, or a serial-to-ethernet convertor. The ATC-1000 is a cost effective solution.

## Protocol
The Mastervolt Soladin protocol is a binary protocol. This protocol was reverse engineered and documented on http://wiki.firestorm.cx/index.php/Soladin (now offline). An archived version of this site is a available at https://web.archive.org/web/20110128190258/http://wiki.firestorm.cx:80/index.php/Soladin.
An alternative source for the protocol description is this Arduino implementation: https://github.com/teding/SolaDin, or the Soladin PCLink traffic analysis stored at https://github.com/jhonniedj/SunnyPi/tree/master/onderzoek/Mastervolt%20soladin%20600.

## Variables
The following variables are set:

| Service | Variable |
| --- | --- |
| urn:mastervolt-com:serviceId:MastervoltPV1 | Flags |
| urn:mastervolt-com:serviceId:MastervoltPV1 | PVVoltage |
| urn:mastervolt-com:serviceId:MastervoltPV1 | PVCurrent |
| urn:mastervolt-com:serviceId:MastervoltPV1 | GridVoltage |
| urn:mastervolt-com:serviceId:MastervoltPV1 | GridFrequency |
| urn:mastervolt-com:serviceId:MastervoltPV1 | OperatingTime |
| urn:micasaverde-com:serviceId:EnergyMetering1 | Watts |
| urn:micasaverde-com:serviceId:EnergyMetering1 | KWH |
| urn:upnp-org:serviceId:TemperatureSensor1 | CurrentTemperature |
| urn:micasaverde-com:serviceId:HaDevice1 | LastUpdate |
