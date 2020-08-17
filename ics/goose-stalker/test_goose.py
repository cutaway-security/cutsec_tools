import os, sys
from scapy.all import *
import goose
import time, datetime
conf.color_theme = BrightTheme()
DEBUG = False
GOOSE_TYPE = 0x88b8

def timeToString(t):
    t4r = struct.unpack('>i',p[:4])[0]
    ptime = datetime.datetime.fromtimestamp(t4r).strftime('%Y-%m-%d- %H:%M:%S')
    return ptime

def curTimeBytes():
    curTime = int(time.time())
    curTimeBytes = struct.pack('>i',int(time.time()))
    return curTimeBytes

#a = rdpcap("wireshark2.pcap")
packets = rdpcap(sys.argv[1])
for p in packets:
    isGoose = False
    try:
        if p.haslayer('Dot1Q'):
            if p[Dot1Q].type == GOOSE_TYPE: isGoose = True
        if p.haslayer('Ether'):
            if p[Ether].type == GOOSE_TYPE: isGoose = True
        if isGoose:
            print(p.show())
    except AttributeError:
        continue


