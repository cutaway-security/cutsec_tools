# Goose-Stalker

## Purpose

Goose-Stalker is a project to analyze and interact with Ethernet types associated with IEC 61850. Currently, the project is focused on Ethernet type 0x88b8 as published by the [goose-IEC61850-scapy](https://github.com/mdehus/goose-IEC61850-scapy). The project has morphed significantly and the direction is to progress this even further.

## Modules and Scripts

* goose.py - Scapy layers to analyze packets (see TODO)
* BER.py - modified version of original project's Basic Encoding Rules (BER). NOTE: this needs to be moved to using Scapy's ASN.1 / BER functionality (see TODO list).
* test_goose.py - script to test the Scapy layers and parsing. Needs to be migrated to an analysis script to output details about devices on the network (See TODO list).
* goose_resend.py - script to identify 0x88b8 packets, toggle boolean values in the goose message, and resend the packet. 
* GOOSE_wireshark.pcap - Wireshark's PCAP file for testing. This does not contain messages with VLAN layers (see TODO list).
* LICENSE - maintained the [goose-IEC61850-scapy](https://github.com/mdehus/goose-IEC61850-scapy)'s original license (see TODO list).
* Pipfile - required Python modules. Probably contains a few more than necessary. See requirements below.

## Requirements and Installation

* [Pipenv](https://docs.pipenv.org/) - Pipfile should contain all required packages, to include a few nice-to-haves.
  * [Scapy](https://github.com/secdev/scapy) - comes with its own set of required packages
  * [iPython](https://ipython.org/)
  * cryptography - may or may not need this
* [Wireshark](https://www.wireshark.org/) - you'll want a second source to analyze PCAPs
  * [Herb Falk’s Skunkwork Network Analyzer](http://www.otb-consultingservices.com/home/shop/skunkworks-network-analyzer/) - a bit dated, but helps to analyze Goose / MMS / IEC61850 packets.
  * [Tshark](https://www.wireshark.org/docs/man-pages/tshark.html) - because command line packet analysis is always more fun.
* Admin Privileges - you'll need administrative privileges to capture and resend data on your system's network interface. 

## TODO

* goose.py: [Scapy](https://github.com/secdev/scapy) provides modules that handle OSI's Abstract Syntax Notation One (ASN.1) and Basic Encoding Rules (BER). This is not currently used by this project. It needs to be migrated to using these modules.
* goose.py: Goose packets can be send with or without VLAN tags (Dot1Q). Layer binding needs to be updated to handle this appropriately.
* goose.py: PacketLenField results in a variable with a raw.load payload. This should be fixed. Updating to Scapy's ASN.1 / BER handling (a separate TODO) might handle this. But, in the meantime, this should be updated to correctly handle the value without the raw.load.
* goose-resend.py: Command line options need to be added to focus on specific targets and allow user to manipulate, at least initially, boolean values.
* goose-resend.py: Update time field in resent packet to be accurate.
* goose-resend.py: Update the sequence numbers to properly progress the this field so that the receiver does not throw out the packet.
* test_goose.py: move this to an actual analysis script that outputs details about the devices on the network.
* PCAPs - include packet captures that represent different IEC 61850 message types and include VLAN/Dot1Q layers.
* LICENSE - should and can the license file be updated to a more current version of open source license?

# goose-IEC61850-scapy

This project was originally forked from the [goose-IEC61850-scapy](https://github.com/mdehus/goose-IEC61850-scapy) project. It has morphed significantly and, thus, it is being moved to a new project. 

> The Generic Object Oriented Substation Events (GOOSE) protocol is defined in IEC 61850 for the purpose of distributing event data across entire substation networks.  The code in this project can be used to provide assistance in decoding / encoding GOOSE packets in a programmatic way.

> Most of the code was thrown together quickly and built so that we could use it to specifically demonstrate an attack against GOOSE in our paper, published in the [IEEE Workshop on Smart Grid Communications](http://ieeexplore.ieee.org/xpl/login.jsp?tp=&arnumber=6477809&url=http%3A%2F%2Fieeexplore.ieee.org%2Fxpls%2Fabs_all.jsp%3Farnumber%3D6477809). [[full text]](http://markdehus.com/SGCOMM.pdf).

> The code comes with absolutely no warranty, and we are not liable if it does something completely unexpected.  If you use this code in an
academic work, please cite our paper.

> Please note that this code depends on the [scapy library](http://www.secdev.org/projects/scapy/).
